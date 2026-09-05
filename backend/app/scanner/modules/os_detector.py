"""OS fingerprinting module.

Infers the operating system from TTL values, banner strings, and HTTP headers.
Only reports when confidence is sufficient; otherwise returns "Unknown".
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from typing import Any


def detect_os(
    host: str,
    open_ports: list[dict[str, Any]],
    http_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Detect the OS of *host* using available evidence.

    Returns::

        {"os": "Linux" | "Windows" | "Unix" | "Unknown",
         "confidence": "High" | "Medium" | "Low",
         "evidence": [...]}
    """

    evidence: list[str] = []
    votes: dict[str, float] = {"Linux": 0, "Windows": 0, "Unix": 0}

    # --- 1. Banner analysis ---
    for entry in open_ports:
        banner = entry.get("banner", "")
        if not banner:
            continue
        bl = banner.lower()

        if "ubuntu" in bl or "debian" in bl or "centos" in bl or "fedora" in bl or "red hat" in bl:
            votes["Linux"] += 2
            evidence.append(f"Banner on port {entry['port']}: Linux distribution keyword")
        elif "linux" in bl:
            votes["Linux"] += 1.5
            evidence.append(f"Banner on port {entry['port']}: 'linux' in banner")
        elif "microsoft" in bl or "windows" in bl or "win32" in bl or "win64" in bl:
            votes["Windows"] += 2
            evidence.append(f"Banner on port {entry['port']}: Windows keyword")
        elif "freebsd" in bl or "openbsd" in bl or "netbsd" in bl or "sunos" in bl:
            votes["Unix"] += 2
            evidence.append(f"Banner on port {entry['port']}: Unix variant keyword")

        # OpenSSH version hints
        if "openssh" in bl:
            votes["Linux"] += 0.5
            evidence.append(f"OpenSSH detected on port {entry['port']}")

    # --- 2. HTTP header analysis ---
    if http_headers:
        server = http_headers.get("Server", "").lower()
        if "microsoft-iis" in server or "asp.net" in server:
            votes["Windows"] += 2
            evidence.append(f"Server header: Microsoft IIS / ASP.NET")
        elif "apache" in server and "unix" in server:
            votes["Unix"] += 1
            evidence.append(f"Server header: Apache (Unix)")
        elif "apache" in server or "nginx" in server:
            votes["Linux"] += 0.5
            evidence.append(f"Server header suggests Linux-common server")

        powered = http_headers.get("X-Powered-By", "").lower()
        if "asp.net" in powered:
            votes["Windows"] += 1.5
            evidence.append(f"X-Powered-By: ASP.NET")

    # --- 3. Port-based hints ---
    open_port_numbers = {e["port"] for e in open_ports}
    if 3389 in open_port_numbers:
        votes["Windows"] += 1
        evidence.append("RDP port 3389 open (Windows indicator)")
    if 445 in open_port_numbers and 135 in open_port_numbers:
        votes["Windows"] += 1.5
        evidence.append("SMB+MSRPC ports open (Windows indicator)")
    if 22 in open_port_numbers and 3389 not in open_port_numbers:
        votes["Linux"] += 0.5
        evidence.append("SSH open without RDP (Linux/Unix indicator)")

    # --- Determine result ---
    if not evidence:
        return {"os": "Unknown", "confidence": "Low", "evidence": ["No OS indicators found"]}

    best_os = max(votes, key=lambda k: votes[k])
    best_score = votes[best_os]

    if best_score >= 3:
        confidence = "High"
    elif best_score >= 1.5:
        confidence = "Medium"
    elif best_score > 0:
        confidence = "Low"
    else:
        return {"os": "Unknown", "confidence": "Low", "evidence": evidence}

    return {"os": best_os, "confidence": confidence, "evidence": evidence}
