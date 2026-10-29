# Android RAT triage and APK signature check

Defensive tools for checking an Android device or APK files. Nothing here is
installed on a device, and nothing is changed unless you confirm each step.

## Files

| File | Purpose |
|---|---|
| `rat_detect.py` | Triage over ADB: device admins, accessibility services, notification listeners, sideloaded apps with high-risk permissions. `--fix` asks before each change. |
| `apk_check.py` | Signature check for APK files or installed apps: schemes (v1/v2/v3), signing certificate, SHA-256 fingerprint, trusted-list match. |
| `test_rat_detect.py` | Unit tests for the parsers in `rat_detect.py`. |
| `test_apk_check.py` | Unit tests for `apk_check.py`, including a real v1 signature made with `keytool` and `jarsigner`. |
| `trusted.txt` | Example trusted fingerprints. Replace with your own. |
| `samples/` | Test APKs: an unsigned one and one signed with a throwaway test key (`test.jks`, password `testpass`). |

## Requirements

- Python 3.10+
- `adb` on PATH for the device features
- Java `keytool` and `jarsigner` for the signature tests
- Optional: `apksigner` from Android build-tools, which `apk_check.py` uses when present

## Run the tests

```
python3 -m unittest -v test_rat_detect test_apk_check
```

## Check an APK

```
python3 apk_check.py samples/signed.apk --trusted trusted.txt
python3 apk_check.py suspicious.apk --json
```

Exit code 1 means the file is unsigned, unreadable, or signed by a key not in the trusted list.

## Check an installed app

```
python3 apk_check.py --installed com.example.app --serial <serial> --trusted trusted.txt
```

This pulls `base.apk` with `adb pull` and then checks it.

## Triage a device

```
python3 rat_detect.py --serial <serial>          # report only
python3 rat_detect.py --serial <serial> --json   # machine-readable
python3 rat_detect.py --serial <serial> --fix    # asks before each change
```

## Known limits

- The `dumpsys` fixtures in `test_rat_detect.py` were written by hand from the AOSP layout. Check the parsers against output from real devices before relying on them.
- `rat_detect.py` has not been run against a real device or emulator.
- Severity weights and the sideloaded-app threshold are heuristics, to be tuned on real samples.
- v2/v3 detection is tested with a synthetic signing block, not a block made by `apksigner`. Verify it on a real v2/v3-signed APK.
- An app cannot remove another app's device admin through the public API. The tool tries `dpm remove-active-admin`, then opens the Security settings screen.
- Runtime permissions can be revoked with `pm revoke` only on Android 6.0 (API 23) and later.
- Without `apksigner`, `keytool` reads only the v1 certificate. A v2/v3-only APK may show `unknown` for the signer.
- A `trusted.txt` entry should be the publisher's real certificate fingerprint, taken from a source you trust.

## Web app (APK check only)

```
TRUSTED_FILE=trusted.txt python3 web_app.py    # http://127.0.0.1:5000
curl -F "apk=@samples/signed.apk" http://127.0.0.1:5000/api/check
```

`web_app.py` checks uploads and deletes them after checking. It binds to
127.0.0.1 by default. If you change `HOST` to make it reachable from other
machines, add authentication first. The device triage (`rat_detect.py`) is
intentionally not exposed on the web, because it controls a phone over ADB.
Uploads are limited to 200 MB (`MAX_UPLOAD_MB`).
