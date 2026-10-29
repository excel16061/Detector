#!/usr/bin/env python3
"""Defensive triage for Android devices over ADB.

Finds signs of remote-access malware that has taken over a device:
  * device admins you did not install,
  * accessibility services and notification listeners that are enabled,
  * sideloaded apps that request high-risk permission combinations.

Nothing is changed on the device unless you pass --fix and confirm each action.

Remediation limits (by design of Android, not of this tool):
  * An app cannot remove another app's device admin through the public API.
    The shell `dpm remove-active-admin` command only works for some packages,
    so when it fails the tool opens the Security settings screen instead.
  * Runtime permissions can be revoked with `pm revoke` on Android 6.0 (API 23)
    and later. Earlier releases grant permissions at install time and cannot
    revoke them, so the tool reports that and skips the step.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field

# Permission -> weight. Weights are heuristic; tune them on real samples.
HIGH_RISK_PERMISSIONS: dict[str, int] = {
    "android.permission.READ_SMS": 2,
    "android.permission.RECEIVE_SMS": 2,
    "android.permission.SEND_SMS": 2,
    "android.permission.SYSTEM_ALERT_WINDOW": 2,
    "android.permission.PROCESS_OUTGOING_CALLS": 2,
    "android.permission.READ_CALL_LOG": 1,
    "android.permission.RECORD_AUDIO": 1,
    "android.permission.CAMERA": 1,
    "android.permission.READ_CONTACTS": 1,
    "android.permission.ACCESS_FINE_LOCATION": 1,
    "android.permission.PACKAGE_USAGE_STATS": 1,
    "android.permission.REQUEST_INSTALL_PACKAGES": 1,
}
SENSITIVE_THRESHOLD = 4          # weight sum that flags a sideloaded app
ADMIN_SECTION_RE = re.compile(r"(?i)enabled device admin|active admin")
COMPONENT_RE = re.compile(r"ComponentInfo\{([\w.]+)/([\w.$/]+)\}")
PERMISSION_LINE_RE = re.compile(r"^\s+((?:android\.permission|com\.[\w.]+\.permission)\.[\w.]+)\s*$")
PACKAGE_LINE_RE = re.compile(r"^package:(\S+)(.*)$")
INSTALLER_RE = re.compile(r"installer=(\S+)")


@dataclass
class Finding:
    severity: str            # "high" | "medium" | "info"
    category: str            # "device_admin" | "accessibility" | "notification_listener" | "sideloaded_app"
    subject: str
    detail: str
    fix: dict | None = None  # machine-readable remediation, used by --fix


@dataclass
class Report:
    sdk: int
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"sdk": self.sdk, "findings": [asdict(f) for f in self.findings]}


# ---------- ADB access ----------

class Adb:
    def __init__(self, serial: str | None = None, adb_bin: str = "adb", timeout: int = 60):
        self.base = [adb_bin] + (["-s", serial] if serial else [])
        self.timeout = timeout

    def shell(self, *cmd: str) -> str:
        proc = subprocess.run(self.base + ["shell", *cmd], capture_output=True,
                              text=True, timeout=self.timeout)
        return proc.stdout

    def shell_ok(self, *cmd: str) -> tuple[bool, str]:
        proc = subprocess.run(self.base + ["shell", *cmd], capture_output=True,
                              text=True, timeout=self.timeout)
        return proc.returncode == 0 and "Exception" not in proc.stdout, (proc.stdout + proc.stderr).strip()


def get_sdk(adb: Adb) -> int:
    raw = adb.shell("getprop", "ro.build.version.sdk").strip()
    return int(raw) if raw.isdigit() else 0


# ---------- parsers (pure functions, unit-tested on fixtures) ----------

def parse_active_admins(dump: str) -> list[str]:
    """Return 'pkg/Class' strings from the admin section of `dumpsys device_policy`."""
    admins: list[str] = []
    header_indent: int | None = None  # indent of the admin section header, if we are inside it
    for line in dump.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if header_indent is not None and indent <= header_indent:
            header_indent = None  # a sibling or outer heading ends the section
        if header_indent is None and ADMIN_SECTION_RE.search(line):
            header_indent = indent
            continue
        if header_indent is not None:
            for pkg, cls in COMPONENT_RE.findall(line):
                admins.append(f"{pkg}/{cls}")
    return sorted(set(admins))


def parse_settings_component_list(value: str) -> list[str]:
    """Parse `settings get secure enabled_accessibility_services` style values."""
    value = (value or "").strip()
    if value in ("", "null"):
        return []
    return sorted({part.strip() for part in value.split(":") if part.strip()})


def parse_package_installers(text: str) -> dict[str, str | None]:
    """Parse `pm list packages -3 -i` output into {package: installer or None}."""
    result: dict[str, str | None] = {}
    for line in text.splitlines():
        m = PACKAGE_LINE_RE.match(line.strip())
        if not m:
            continue
        inst = INSTALLER_RE.search(m.group(2))
        installer = inst.group(1) if inst else None
        if installer in ("null", ""):
            installer = None
        result[m.group(1)] = installer
    return result


def parse_requested_permissions(dump: str) -> set[str]:
    """Extract the 'requested permissions:' block of `dumpsys package <pkg>`."""
    perms: set[str] = set()
    lines = dump.splitlines()
    for i, line in enumerate(lines):
        if line.strip().lower() == "requested permissions:":
            header_indent = len(line) - len(line.lstrip())
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    continue
                indent = len(nxt) - len(nxt.lstrip())
                if indent <= header_indent:
                    break
                m = PERMISSION_LINE_RE.match(nxt)
                if m:
                    perms.add(m.group(1))
            break
    return perms


def assess_permissions(perms: set[str]) -> tuple[int, list[str]]:
    hits = sorted(p for p in perms if p in HIGH_RISK_PERMISSIONS)
    score = sum(HIGH_RISK_PERMISSIONS[p] for p in hits)
    return score, hits


# ---------- analysis ----------

def analyze(adb: Adb, sdk: int) -> Report:
    report = Report(sdk=sdk)

    admin_dump = adb.shell("dumpsys", "device_policy")
    for comp in parse_active_admins(admin_dump):
        pkg = comp.split("/")[0]
        report.findings.append(Finding(
            severity="high", category="device_admin", subject=comp,
            detail="Active device administrator. Malware uses this to block uninstall and lock the screen.",
            fix={"action": "remove_admin", "component": comp, "package": pkg}))

    accessibility = parse_settings_component_list(
        adb.shell("settings", "get", "secure", "enabled_accessibility_services"))
    for svc in accessibility:
        pkg = svc.split("/")[0]
        report.findings.append(Finding(
            severity="high", category="accessibility", subject=svc,
            detail="Enabled accessibility service. It can read the screen and tap for the user.",
            fix={"action": "disable_accessibility", "service": svc, "package": pkg}))

    listeners = parse_settings_component_list(
        adb.shell("settings", "get", "secure", "enabled_notification_listeners"))
    for svc in listeners:
        report.findings.append(Finding(
            severity="medium", category="notification_listener", subject=svc,
            detail="Notification listener. It can read all incoming notifications, including OTP codes."))

    installers = parse_package_installers(adb.shell("pm", "list", "packages", "-3", "-i"))
    for pkg, installer in sorted(installers.items()):
        if installer is not None:
            continue  # installed through a store, so not sideloaded
        dump = adb.shell("dumpsys", "package", pkg)
        perms = parse_requested_permissions(dump)
        score, hits = assess_permissions(perms)
        if score >= SENSITIVE_THRESHOLD:
            report.findings.append(Finding(
                severity="high" if score >= 2 * SENSITIVE_THRESHOLD else "medium",
                category="sideloaded_app", subject=pkg,
                detail=f"Sideloaded (no installer) with high-risk permissions (score {score}): {', '.join(hits)}",
                fix={"action": "revoke_permissions", "package": pkg, "permissions": hits}))
    return report


# ---------- remediation (each step requires explicit confirmation) ----------

def apply_fix(adb: Adb, finding: Finding, sdk: int) -> str:
    fix = finding.fix or {}
    action = fix.get("action")
    if action == "remove_admin":
        ok, out = adb.shell_ok("dpm", "remove-active-admin", fix["component"])
        if ok:
            return f"removed admin {fix['component']}"
        adb.shell("am", "start", "-a", "android.settings.SECURITY_SETTINGS")
        return (f"shell removal refused ({out or 'no output'}); opened Security settings "
                f"so you can deactivate {fix['package']} manually")
    if action == "disable_accessibility":
        remaining = [s for s in parse_settings_component_list(
            adb.shell("settings", "get", "secure", "enabled_accessibility_services"))
            if s != fix["service"]]
        value = ":".join(remaining) if remaining else "null"
        adb.shell("settings", "put", "secure", "enabled_accessibility_services", value)
        return f"disabled accessibility service {fix['service']}"
    if action == "revoke_permissions":
        if sdk < 23:
            return "skipped: runtime permissions cannot be revoked before Android 6.0 (API 23)"
        done = []
        for perm in fix["permissions"]:
            ok, _ = adb.shell_ok("pm", "revoke", fix["package"], perm)
            if ok:
                done.append(perm)
        return f"revoked {len(done)}/{len(fix['permissions'])} permissions from {fix['package']}"
    return "no automatic fix for this finding"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serial", help="adb device serial when several devices are connected")
    ap.add_argument("--adb", default="adb", help="path to adb binary")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--fix", action="store_true", help="offer to remediate each finding (asks per item)")
    args = ap.parse_args(argv)

    adb = Adb(args.serial, args.adb)
    try:
        sdk = get_sdk(adb)
        report = analyze(adb, sdk)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"adb failed: {exc}. Check that USB debugging is on and the device is authorised.",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Android API {sdk}: {len(report.findings)} finding(s)")
        for f in report.findings:
            print(f"[{f.severity.upper()}] {f.category}: {f.subject}\n    {f.detail}")
        if not report.findings:
            print("No indicators found. This is not proof the device is clean.")

    if args.fix:
        for f in report.findings:
            if not f.fix:
                continue
            answer = input(f"Apply fix to {f.subject} ({f.fix['action']})? [y/N] ").strip().lower()
            if answer == "y":
                print("  ->", apply_fix(adb, f, sdk))
    return 1 if any(f.severity == "high" for f in report.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
