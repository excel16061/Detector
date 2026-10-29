#!/usr/bin/env python3
"""Check the signing certificate of APK files, or of apps installed on a device.

For each APK it reports which signature schemes are present (v1 JAR, v2, v3),
the signing certificate's subject and SHA-256 fingerprint, and whether that
fingerprint is in your trusted list. A package signed by a different key than
the one you trust is a strong sign of a repackaged or trojanized app.

Usage:
  apk_check.py app.apk [more.apk ...] [--trusted trusted.txt] [--json]
  apk_check.py --installed com.example.app [--serial SERIAL] [--trusted trusted.txt]

trusted.txt holds one SHA-256 fingerprint per line (colons and case are ignored).
Lines starting with # are comments.

Uses apksigner from the Android SDK build-tools when it is on PATH, otherwise
keytool, which reads the v1 certificate. v2/v3 presence is detected from the
APK Signing Block directly.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_ID = 0x7109871A  # APK Signature Scheme v2 block
V3_ID = 0xF05368C0  # APK Signature Scheme v3 block
V31_ID = 0x1B93AD61  # v3.1 block
V1_CERT_RE = re.compile(r"^META-INF/[^/]+\.(RSA|DSA|EC)$", re.IGNORECASE)
SHA256_RE = re.compile(r"SHA-?256[^:]*:\s*([0-9A-Fa-f:]{64,})")


@dataclass
class ApkResult:
    path: str
    schemes: list[str] = field(default_factory=list)
    signer_subject: str | None = None
    sha256: str | None = None
    trusted: bool | None = None  # None when no trusted list was given
    problems: list[str] = field(default_factory=list)


def normalize_fp(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").lower()


def load_trusted(path: str | None) -> set[str] | None:
    if not path:
        return None
    fps = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                fps.add(normalize_fp(line))
    return fps


def detect_schemes(path: str) -> list[str]:
    """Detect v1/v2/v3 signatures without any external tool."""
    schemes: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    if any(V1_CERT_RE.match(n) for n in names) and "META-INF/MANIFEST.MF" in names:
        schemes.append("v1")
    # Layout just before the central directory (CD):
    #   [u64 size S][id-value pairs, S-8 bytes][u64 size S][16-byte magic][CD]
    # EOCD record: CD offset is the u32 at byte 16 of the record.
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(size - (1 << 16) - 22, 0))
        tail = fh.read()
        eocd = tail.rfind(b"PK\x05\x06")
        if eocd == -1 or eocd + 20 > len(tail):
            return schemes
        cd_offset = int.from_bytes(tail[eocd + 16:eocd + 20], "little")
        read_from = max(cd_offset - (1 << 20), 0)
        fh.seek(read_from)
        region = fh.read(cd_offset - read_from)
    pos = region.rfind(APK_SIG_BLOCK_MAGIC)
    if pos < 8:
        return schemes  # v1-only APK
    body_len = int.from_bytes(region[pos - 8:pos], "little")  # S: bytes after the first size field
    start = pos + 8 - body_len  # block ends 16 bytes past the magic; first size field is here
    if start < 0:
        return schemes
    ids: set[int] = set()
    j = start + 8
    end = pos - 8  # the second size field sits here
    while j + 12 <= end:
        pair_len = int.from_bytes(region[j:j + 8], "little")
        if pair_len < 4:
            break
        ids.add(int.from_bytes(region[j + 8:j + 12], "little"))
        j += 8 + pair_len
    if V2_ID in ids:
        schemes.append("v2")
    if V3_ID in ids or V31_ID in ids:
        schemes.append("v3")
    return schemes


def cert_info_apksigner(apksigner: str, path: str) -> tuple[str | None, str | None]:
    proc = subprocess.run([apksigner, "verify", "--print-certs", path],
                          capture_output=True, text=True, timeout=120)
    text = proc.stdout + proc.stderr
    subj = re.search(r"Signer #1 certificate DN:\s*(.+)", text)
    sha = re.search(r"Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]+)", text)
    return (subj.group(1).strip() if subj else None, sha.group(1) if sha else None)


def cert_info_keytool(path: str) -> tuple[str | None, str | None]:
    """Read the first v1 certificate from the JAR and print its fingerprint with keytool."""
    with zipfile.ZipFile(path) as zf:
        certs = [n for n in zf.namelist() if V1_CERT_RE.match(n)]
        if not certs:
            return None, None
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "cert.bin")
            with open(out, "wb") as fh:
                fh.write(zf.read(sorted(certs)[0]))
            proc = subprocess.run(["keytool", "-printcert", "-file", out],
                                  capture_output=True, text=True, timeout=60)
    text = proc.stdout + proc.stderr
    owner = re.search(r"Owner:\s*(.+)", text)
    sha = SHA256_RE.search(text)
    return (owner.group(1).strip() if owner else None,
            normalize_fp(sha.group(1)) if sha else None)


def check_apk(path: str, trusted: set[str] | None, apksigner: str | None) -> ApkResult:
    res = ApkResult(path=path)
    try:
        res.schemes = detect_schemes(path)
    except zipfile.BadZipFile:
        res.problems.append("not a valid zip/APK file")
        return res
    if not res.schemes:
        res.problems.append("no signature found: unsigned APKs cannot be installed on modern Android")

    subject = sha = None
    if apksigner:
        subject, sha = cert_info_apksigner(apksigner, path)
    if not sha:
        subject, sha = cert_info_keytool(path)
    if sha:
        res.sha256 = normalize_fp(sha)
        res.signer_subject = subject
    if "v1" in res.schemes and "v2" not in res.schemes and "v3" not in res.schemes:
        res.problems.append("v1-only signature: vulnerable to Janus-style tampering on old Android; "
                            "re-sign with v2 or v3")
    if trusted is not None and res.sha256:
        res.trusted = res.sha256 in trusted
        if not res.trusted:
            res.problems.append("signing certificate is NOT in the trusted list")
    return res


def pull_installed(package: str, serial: str | None, workdir: str) -> str:
    base = ["adb"] + (["-s", serial] if serial else [])
    proc = subprocess.run(base + ["shell", "pm", "path", package],
                          capture_output=True, text=True, timeout=60)
    paths = [line.split(":", 1)[1].strip() for line in proc.stdout.splitlines()
             if line.startswith("package:")]
    if not paths:
        raise RuntimeError(f"package {package} not installed (or adb cannot see it)")
    # Split APKs have several entries; base.apk holds the signature we need.
    target = next((p for p in paths if p.endswith("base.apk")), paths[0])
    local = os.path.join(workdir, f"{package}.apk")
    subprocess.run(base + ["pull", target, local], check=True, capture_output=True, timeout=300)
    return local


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apks", nargs="*", help="APK files to check")
    ap.add_argument("--installed", metavar="PACKAGE", help="pull and check an installed package via adb")
    ap.add_argument("--serial", help="adb device serial")
    ap.add_argument("--trusted", help="file of trusted SHA-256 fingerprints, one per line")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.apks and not args.installed:
        ap.error("give at least one APK or --installed PACKAGE")

    try:
        trusted = load_trusted(args.trusted)
    except OSError as exc:
        print(f"cannot read trusted list: {exc}", file=sys.stderr)
        return 2
    apksigner = shutil.which("apksigner")
    results: list[ApkResult] = []
    with tempfile.TemporaryDirectory() as tmp:
        targets = list(args.apks)
        if args.installed:
            try:
                targets.append(pull_installed(args.installed, args.serial, tmp))
            except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
                print(f"could not pull {args.installed}: {exc}", file=sys.stderr)
                return 2
        for path in targets:
            results.append(check_apk(path, trusted, apksigner))

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        for r in results:
            print(f"== {r.path}")
            print(f"   schemes : {', '.join(r.schemes) or 'none'}")
            print(f"   signer  : {r.signer_subject or 'unknown'}")
            print(f"   sha256  : {r.sha256 or 'unknown'}")
            if r.trusted is not None:
                print(f"   trusted : {'yes' if r.trusted else 'NO'}")
            for p in r.problems:
                print(f"   ! {p}")
    bad = any(r.problems and any(k in p for p in r.problems for k in ("NOT", "no signature", "not a valid"))
              for r in results)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
