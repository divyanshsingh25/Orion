"""CVE lookup module.

Static mapping of service+version → known CVEs.
Only reports *potential* vulnerabilities with proper evidence.

Version matching uses normalized comparison and always reports as
"Potentially Affected" because vendors may backport security patches
without changing the major version number.
"""

from __future__ import annotations

import re
from typing import Any


# Static CVE database: service_name_lower → list of version-range entries
# Each entry: {"versions": (min, max), "fix_version": str, "cve": str,
#              "cvss": float, "severity": str, "description": str,
#              "remediation": str}
_CVE_DB: dict[str, list[dict[str, Any]]] = {
    "openssh": [
        {"versions": ("7.0", "7.7"), "fix_version": "7.8", "cve": "CVE-2018-15473", "cvss": 5.3, "severity": "Medium",
         "description": "OpenSSH user enumeration vulnerability",
         "remediation": "Upgrade to OpenSSH 7.8 or later"},
        {"versions": ("8.0", "8.3"), "fix_version": "8.4", "cve": "CVE-2020-15778", "cvss": 7.8, "severity": "High",
         "description": "OpenSSH scp command injection vulnerability",
         "remediation": "Upgrade to OpenSSH 8.4 or later"},
        {"versions": ("5.0", "9.2"), "fix_version": "9.3p2", "cve": "CVE-2023-38408", "cvss": 9.8, "severity": "Critical",
         "description": "OpenSSH PKCS#11 remote code execution via ssh-agent forwarding",
         "remediation": "Upgrade to OpenSSH 9.3p2 or later"},
        {"versions": ("8.5", "9.7"), "fix_version": "9.8", "cve": "CVE-2024-6387", "cvss": 8.1, "severity": "High",
         "description": "OpenSSH RegreSSHion: signal handler race condition (RCE)",
         "remediation": "Upgrade to OpenSSH 9.8 or later"},
    ],
    "apache": [
        {"versions": ("2.4.0", "2.4.49"), "fix_version": "2.4.50", "cve": "CVE-2021-41773", "cvss": 7.5, "severity": "High",
         "description": "Apache HTTP Server path traversal and disclosure",
         "remediation": "Upgrade to Apache 2.4.50 or later"},
        {"versions": ("2.4.0", "2.4.51"), "fix_version": "2.4.52", "cve": "CVE-2021-44790", "cvss": 9.8, "severity": "Critical",
         "description": "Apache HTTP Server mod_lua buffer overflow",
         "remediation": "Upgrade to Apache 2.4.52 or later"},
        {"versions": ("2.4.0", "2.4.54"), "fix_version": "2.4.56", "cve": "CVE-2023-25690", "cvss": 9.8, "severity": "Critical",
         "description": "Apache HTTP Server mod_proxy HTTP request smuggling",
         "remediation": "Upgrade to Apache 2.4.56 or later"},
    ],
    "nginx": [
        {"versions": ("0.6.18", "1.20.0"), "fix_version": "1.20.1", "cve": "CVE-2021-23017", "cvss": 7.7, "severity": "High",
         "description": "Nginx DNS resolver off-by-one heap write vulnerability",
         "remediation": "Upgrade to Nginx 1.20.1 or 1.21.0"},
        {"versions": ("1.0.0", "1.22.1"), "fix_version": "1.23.2", "cve": "CVE-2022-41741", "cvss": 7.8, "severity": "High",
         "description": "Nginx mp4 module memory corruption vulnerability",
         "remediation": "Upgrade to Nginx 1.23.2 or later"},
    ],
    "microsoft iis": [
        {"versions": ("7.0", "10.0"), "fix_version": "N/A (patch required)", "cve": "CVE-2017-7269", "cvss": 9.8, "severity": "Critical",
         "description": "IIS WebDAV ScStoragePathFromUrl buffer overflow",
         "remediation": "Apply Microsoft security patches or disable WebDAV"},
    ],
    "mysql": [
        {"versions": ("5.5.0", "5.7.37"), "fix_version": "5.7.38", "cve": "CVE-2022-21417", "cvss": 4.9, "severity": "Medium",
         "description": "MySQL Server InnoDB unspecified vulnerability",
         "remediation": "Upgrade to MySQL 5.7.38 or 8.0.29+"},
        {"versions": ("8.0.0", "8.0.32"), "fix_version": "8.0.33", "cve": "CVE-2023-21977", "cvss": 4.9, "severity": "Medium",
         "description": "MySQL Server optimizer unspecified vulnerability",
         "remediation": "Upgrade to MySQL 8.0.33 or later"},
    ],
    "postgresql": [
        {"versions": ("12.0", "14.7"), "fix_version": "14.8", "cve": "CVE-2023-2454", "cvss": 7.2, "severity": "High",
         "description": "PostgreSQL schema privilege escalation via CREATE SCHEMA",
         "remediation": "Upgrade to PostgreSQL 14.8, 15.3 or later"},
        {"versions": ("11.0", "15.2"), "fix_version": "15.3", "cve": "CVE-2023-2455", "cvss": 5.4, "severity": "Medium",
         "description": "PostgreSQL row security bypass via MERGE command",
         "remediation": "Upgrade to latest stable PostgreSQL release"},
    ],
    "redis": [
        {"versions": ("2.0", "6.2.6"), "fix_version": "6.2.7", "cve": "CVE-2022-0543", "cvss": 10.0, "severity": "Critical",
         "description": "Redis Lua sandbox escape (Debian/Ubuntu specific)",
         "remediation": "Upgrade to Redis 6.2.7+ or 7.0+ and update OS packages"},
        {"versions": ("5.0", "7.0.4"), "fix_version": "7.0.5", "cve": "CVE-2022-35977", "cvss": 5.5, "severity": "Medium",
         "description": "Redis integer overflow in SETRANGE/SORT commands",
         "remediation": "Upgrade to Redis 7.0.5 or later"},
    ],
    "vsftpd": [
        {"versions": ("2.3.4", "2.3.4"), "fix_version": "3.0", "cve": "CVE-2011-2523", "cvss": 9.8, "severity": "Critical",
         "description": "vsftpd 2.3.4 backdoor (smiley face trigger)",
         "remediation": "Upgrade to vsftpd 3.x or use an alternative FTP server"},
    ],
}


def _normalize_version(version_str: str) -> str:
    """Strip OS/distribution suffixes from version strings.

    Examples:
        "7.4p1"              -> "7.4"
        "2.4.41-4ubuntu3"    -> "2.4.41"
        "8.0.32-0ubuntu0.20" -> "8.0.32"
        "1.20.1"             -> "1.20.1"
    """
    # Remove common suffixes: p1, -4ubuntu3, etc.
    cleaned = re.split(r"[-+~]", version_str)[0]
    # Remove trailing non-numeric suffixes like 'p1', 'beta1'
    cleaned = re.sub(r"[a-zA-Z]\w*$", "", cleaned)
    return cleaned.strip().rstrip(".")


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison."""
    normalized = _normalize_version(version_str)
    parts = re.findall(r"\d+", normalized)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Check if *version* falls within [min_ver, max_ver]."""
    v = _parse_version(version)
    lo = _parse_version(min_ver)
    hi = _parse_version(max_ver)
    return lo <= v <= hi


def _version_below_fix(version: str, fix_ver: str) -> bool:
    """Check if version is below the fix version.

    Returns True if version < fix_version (meaning potentially affected).
    """
    if not fix_ver or fix_ver.startswith("N/A"):
        return True  # No known fix version
    v = _parse_version(version)
    fix = _parse_version(fix_ver)
    return v < fix


def lookup_cves(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Look up known CVEs for detected services.

    Confidence levels:
      - "Potentially Affected" — version in vulnerable range but vendor may
        have backported patches (NEVER auto-confirmed)
      - "Version Unknown" — service detected but version not extracted
      - "Not Affected" (not reported) — version above fix version

    Parameters
    ----------
    services
        Output from ``service_detector.detect_services``.

    Returns
    -------
    list[dict]
        Findings for each matching CVE.
    """

    findings: list[dict[str, Any]] = []

    for svc in services:
        service_name = (svc.get("service") or "").strip()
        version = (svc.get("version") or "").strip()
        port = svc.get("port", 0)

        if not service_name:
            continue

        key = service_name.lower()
        cve_entries = _CVE_DB.get(key, [])

        if not cve_entries:
            continue

        if version:
            normalized = _normalize_version(version)
            # Check for version-specific matches
            for entry in cve_entries:
                min_v, max_v = entry["versions"]
                fix_v = entry.get("fix_version", "")

                if _version_in_range(normalized, min_v, max_v):
                    # Version is in vulnerable range — but may have backported patches
                    # Never auto-confirm; always "Potentially Affected"
                    below_fix = _version_below_fix(normalized, fix_v)

                    if not below_fix:
                        # Version is at or above fix — skip
                        continue

                    findings.append({
                        "title": f"{service_name} {version} potentially affected by {entry['cve']}",
                        "description": (
                            f"{service_name} {version} detected on port {port}. "
                            f"Version is within the vulnerable range ({min_v}–{max_v}) for "
                            f"{entry['cve']}: {entry['description']}. "
                            f"Note: vendor-backported patches may not be reflected in "
                            f"the version banner. Verify with vendor-specific package checks."
                        ),
                        "finding_type": "service_vulnerability",
                        "severity": entry["severity"],
                        "cvss": entry["cvss"],
                        "cve": entry["cve"],
                        "confidence": "Medium",
                        "verification_status": "potential",
                        "detection_reason": (
                            f"Banner version {version} (normalized: {normalized}) "
                            f"is within vulnerable range {min_v}–{max_v}. "
                            f"Fix version: {fix_v}. "
                            f"Vendor backports may apply — manual verification recommended."
                        ),
                        "evidence": (
                            f"Service: {service_name} {version} on port {port}/tcp\n"
                            f"Banner: {svc.get('evidence', 'N/A')}\n"
                            f"Normalized version: {normalized}\n"
                            f"Vulnerable range: {min_v} – {max_v}\n"
                            f"Fix version: {fix_v}"
                        ),
                        "remediation": entry["remediation"],
                        "url": f"port {port}/tcp",
                        "method": "N/A",
                        "payload": "N/A",
                        "parameter": None,
                        "cwe": "CWE-1035",
                        "owasp": "A06:2021 - Vulnerable and Outdated Components",
                        "port": port,
                        "service": service_name,
                        "version": version,
                    })
        else:
            # No version detected — report as low-confidence informational
            # Only for services with critical CVE history
            has_critical = any(e["severity"] in ("Critical", "High") for e in cve_entries)
            if has_critical:
                findings.append({
                    "title": f"{service_name} detected on port {port} — version unknown, CVE review recommended",
                    "description": (
                        f"{service_name} detected on port {port} without version information. "
                        f"This service has known CVEs. Determine the exact version to assess risk."
                    ),
                    "finding_type": "service_vulnerability",
                    "severity": "Info",
                    "cvss": 0.0,
                    "confidence": "Low",
                    "verification_status": "potential",
                    "detection_reason": (
                        f"Service {service_name} detected on port {port} without version. "
                        f"Unable to determine CVE applicability."
                    ),
                    "evidence": f"Service: {service_name} on port {port}/tcp (version unknown)",
                    "remediation": "Identify the exact service version and check for applicable CVEs",
                    "url": f"port {port}/tcp",
                    "method": "N/A",
                    "payload": "N/A",
                    "parameter": None,
                    "cwe": "CWE-1035",
                    "owasp": "A06:2021 - Vulnerable and Outdated Components",
                    "port": port,
                    "service": service_name,
                    "version": None,
                })

    return findings
