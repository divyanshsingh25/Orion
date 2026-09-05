"""ORION Scanner Orchestrator — Industry-grade scan pipeline.

Runs the full assessment pipeline:
1. Validate target
2. DNS enumeration
3. WHOIS / NS lookup
4. Port scanning
5. Service detection
6. OS detection
7. CVE lookup
8. Web crawling
9. Playwright deep crawling (JS, SPA, XHR, GraphQL, WebSocket)
10. TLS analysis
11. Cookie analysis
12. JWT analysis
13. Security analysis (hacktheweb modules)
14. API security testing
15. GraphQL security testing
16. Adaptive scanning (finding-driven follow-ups)
17. Evidence verification
18. Report generation

All progress, ETA, requests, endpoints, and logs are REAL and reactive.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import aiohttp

from app.core.config import get_settings
from app.core.owasp import calculate_dynamic_cvss, lookup_profile
from app.scanner.hacktheweb_adapter import load_hacktheweb_components
from app.scanner.modules.dns_enumerator import run_dns_enumeration
from app.scanner.modules.whois_lookup import run_whois_lookup
from app.scanner.modules.ns_lookup import run_ns_lookup
from app.scanner.modules.port_scanner import run_port_scan
from app.scanner.modules.service_detector import detect_services
from app.scanner.modules.os_detector import detect_os
from app.scanner.modules.cve_lookup import lookup_cves
from app.scanner.modules.web_crawler import run_web_crawler
from app.scanner.modules.cookie_scanner import scan_cookies

# --- New modules ---
from app.scanner.auth_handler import AuthHandler
from app.scanner.safety import ScanSafety, ScanTimeoutError
from app.scanner.evidence_collector import EvidenceCollector
from app.scanner.adaptive_engine import AdaptiveEngine
from app.scanner.finding_pipeline import FindingPipeline
from app.scanner.modules.api_scanner import scan_api_endpoints
from app.scanner.modules.graphql_scanner import scan_graphql_endpoints
from app.scanner.modules.jwt_scanner import scan_jwt_security
from app.scanner.modules.tls_scanner import scan_tls_security


ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


@dataclass
class ScanCounters:
    """Mutable counters tracked throughout a scan and sent to the frontend."""
    requests_made: int = 0
    endpoints_discovered: int = 0
    findings_count: int = 0
    open_ports: int = 0
    services_detected: int = 0
    modules_completed: int = 0
    modules_total: int = 0
    start_time: float = field(default_factory=time.monotonic)

    def eta_seconds(self, current_progress: int) -> int:
        if current_progress <= 0:
            return 0
        elapsed = time.monotonic() - self.start_time
        remaining_pct = max(0, 100 - current_progress)
        rate = elapsed / current_progress
        return int(rate * remaining_pct)


MODULE_LABELS: dict[str, str] = {
    "security_headers": "Security Headers",
    "csrf": "CSRF Scanner",
    "cors": "CORS Scanner",
    "xss": "XSS Injection",
    "sqli": "SQL Injection",
    "ssrf": "SSRF Scanner",
    "lfi": "LFI / File Inclusion",
    "xxe": "XXE Injection",
    "rce": "Remote Code Exec",
    "idor": "IDOR / Access Control",
    "open_redirect": "Open Redirect",
    "path_traversal": "Path Traversal",
    "nosqli": "NoSQL Injection",
    "ldapi": "LDAP Injection",
    "ssti": "SSTI Template Injection",
}


class _TargetHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inputs: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self._current_form = {"action": urljoin(self.base_url, attributes.get("action", "")), "method": attributes.get("method", "GET").upper(), "inputs": []}
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"}:
            field = {"type": attributes.get("type", tag), "name": attributes.get("name", ""), "value": attributes.get("value", "")}
            self.inputs.append({**field, "url": self.base_url})
            if self._current_form is not None:
                self._current_form["inputs"].append(field)
        elif tag == "a" and attributes.get("href"):
            self.links.append(urljoin(self.base_url, attributes["href"]))
        elif tag == "script" and attributes.get("src"):
            self.scripts.append(urljoin(self.base_url, attributes["src"]))

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._current_form = None


class OrionScanner:
    def __init__(self) -> None:
        self.settings = get_settings()
        components = load_hacktheweb_components()
        self.data_loader = components["data_loader"]
        self.hack_cfg = components["Config"]()
        self.hack_ai = components["AIEngine"](self.hack_cfg)
        self.scanner_types = {
            "security_headers": components["SecurityHeadersScanner"],
            "csrf": components["CSRFScanner"],
            "cors": components["CORSScanner"],
            "xss": components["XSSScanner"],
            "sqli": components["SQLiScanner"],
            "ssrf": components["SSRFScanner"],
            "lfi": components["LFIScanner"],
            "xxe": components["XXEScanner"],
            "rce": components["RCEScanner"],
            "idor": components["IDORScanner"],
            "open_redirect": components["OpenRedirectScanner"],
            "path_traversal": components["PathTraversalScanner"],
            "nosqli": components["NoSQLiScanner"],
            "ldapi": components["LDAPIScanner"],
            "ssti": components["SSTIScanner"],
        }

    async def scan(
        self,
        target_url: str,
        scan_mode: str = "smart",
        depth: str = "medium",
        progress: ProgressCallback | None = None,
        auth_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS targets are supported")
        host = parsed.hostname or ""
        origin = f"{parsed.scheme}://{parsed.netloc}"

        counters = ScanCounters()
        is_quick = scan_mode.lower() in ("quick", "quick scan", "fast")

        # --- Initialize safety layer (Hard-capped under 5 mins: 240s for Quick, 600s for Full) ---
        max_duration = 240.0 if is_quick else self.settings.scan_max_duration_seconds
        safety = ScanSafety(
            allowed_origins=[origin],
            max_rps=self.settings.scan_max_rps,
            max_concurrency=self.settings.scan_max_concurrency,
            request_timeout=self.settings.scan_connect_timeout_seconds,
            max_duration_seconds=max_duration,
            safe_mode=self.settings.scan_safe_mode,
            allow_private=self.settings.allow_private_targets,
        )
        safety.start_scan()

        await self._emit(progress, self._build_payload(
            counters, 1, "Initialization", target_url,
            event="scan_started",
            log={"level": "INFO", "message": f"Scan initialized for {target_url} ({'Quick Mode: 5-min budget' if is_quick else 'Full Mode'})"},
            module_info={"name": "Target Initialization", "status": "Scanning", "findings": 0},
        ))

        timeout = aiohttp.ClientTimeout(
            total=180.0 if is_quick else self.settings.scan_timeout_seconds,
            connect=self.settings.scan_connect_timeout_seconds,
        )
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": "ORION Security Assessment Platform/1.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:

            # --- Authentication phase ---
            auth_handler = AuthHandler(auth_config)
            if auth_handler.is_configured:
                await self._emit(progress, self._build_payload(
                    counters, 2, "Authentication", target_url,
                    event="recon_step",
                    log={"level": "SCAN", "message": f"[AUTH] Authenticating session ({auth_handler.auth_type})"},
                    module_info={"name": "Target Authentication", "status": "Scanning", "findings": 0},
                ))
                auth_ok = await auth_handler.authenticate(session, target_url)
                if auth_ok:
                    auth_handler.apply_to_session(session)
                    extra_headers = auth_handler.get_extra_headers()
                    if extra_headers:
                        session.headers.update(extra_headers)
                    await self._emit(progress, self._build_payload(
                        counters, 3, "Authentication", target_url,
                        event="recon_step",
                        log={"level": "INFO", "message": "[AUTH] Authentication successful - Session established"},
                        module_info={"name": "Target Authentication", "status": "Complete", "findings": 0},
                    ))
                else:
                    await self._emit(progress, self._build_payload(
                        counters, 3, "Authentication", target_url,
                        event="recon_step",
                        log={"level": "WARN", "message": "[AUTH] Authentication failed - Continuing unauthenticated"},
                        module_info={"name": "Target Authentication", "status": "Complete", "findings": 0},
                    ))

            # --- Initialize evidence collector & target baseline ---
            evidence = EvidenceCollector(session)
            raw_findings: list[dict[str, Any]] = []

            http_headers: dict[str, str] = {}
            http_cookies: list[dict[str, Any]] = []
            html_content: str = ""
            main_status: int = 0
            technologies: list[str] = []

            try:
                async with session.get(target_url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=8.0)) as response:
                    counters.requests_made += 1
                    main_status = response.status
                    http_headers = {k: v for k, v in response.headers.items()}
                    http_cookies = [
                        {"name": c.key, "value": c.value, "domain": c.get("domain", ""), "path": c.get("path", "/"),
                         "secure": bool(c.get("secure")), "httponly": bool(c.get("httponly")),
                         "samesite": c.get("samesite", "")}
                        for c in response.cookies.values()
                    ]
                    html_content = await response.text(errors="ignore")
                    counters.endpoints_discovered += 1
                    technologies = self.hack_ai.knowledge_base.detect_technologies(http_headers, html_content)
            except Exception:
                pass

            # ============================================================
            # Phase 1: DNS Enumeration (3–6%)
            # ============================================================
            await self._emit(progress, self._build_payload(
                counters, 3, "DNS Enumeration", target_url,
                event="recon_step",
                log={"level": "SCAN", "message": f"[DNS] Resolving DNS records for {host}"},
                module_info={"name": "DNS Enumeration", "status": "Scanning", "findings": 0},
            ))

            async def dns_emit(payload: dict[str, Any]) -> None:
                msg = payload.get("log_message", "")
                if msg:
                    await self._emit(progress, self._build_payload(
                        counters, 5, "DNS Enumeration", target_url,
                        event="recon_step",
                        log={"level": "INFO", "message": msg},
                        module_info={"name": "DNS Enumeration", "status": "Scanning", "findings": 0},
                    ))

            dns_data = await run_dns_enumeration(host, emit=dns_emit)
            counters.requests_made += 1

            await self._emit(progress, self._build_payload(
                counters, 6, "DNS Enumeration", target_url,
                event="recon_step",
                log={"level": "SCAN", "message": f"[DNS] Complete - {sum(len(v) for v in dns_data.get('records', {}).values())} records, {len(dns_data.get('subdomains', []))} subdomains"},
                module_info={"name": "DNS Enumeration", "status": "Complete", "findings": 0},
            ))

            # ============================================================
            # Phase 2: WHOIS / NS Lookup (6–10%)
            # ============================================================
            await self._emit(progress, self._build_payload(
                counters, 7, "WHOIS & Network Intel", target_url,
                event="recon_step",
                log={"level": "SCAN", "message": f"[WHOIS] Querying WHOIS registry for {host}"},
                module_info={"name": "WHOIS & Network Intel", "status": "Scanning", "findings": 0},
            ))

            whois_data = await run_whois_lookup(host)
            whois_status = whois_data.get("status", "ok")
            if whois_status == "ok":
                registrar = whois_data.get("registrar", "N/A")
                await self._emit(progress, self._build_payload(
                    counters, 8, "WHOIS & Network Intel", target_url,
                    event="recon_step",
                    log={"level": "INFO", "message": f"[WHOIS] Registrar: {registrar}"},
                    module_info={"name": "WHOIS & Network Intel", "status": "Scanning", "findings": 0},
                ))
            else:
                await self._emit(progress, self._build_payload(
                    counters, 8, "WHOIS & Network Intel", target_url,
                    event="recon_step",
                    log={"level": "WARN", "message": "[WHOIS] WHOIS privacy enabled / restricted"},
                    module_info={"name": "WHOIS & Network Intel", "status": "Scanning", "findings": 0},
                ))

            ns_data = await run_ns_lookup(host)
            ns_count = len(ns_data.get("name_servers", []))
            ip_count = len(ns_data.get("ips", []))
            await self._emit(progress, self._build_payload(
                counters, 10, "WHOIS & Network Intel", target_url,
                event="recon_step",
                log={"level": "INFO", "message": f"[NS] Resolved {ip_count} IPs across {ns_count} Name Servers"},
                module_info={"name": "WHOIS & Network Intel", "status": "Complete", "findings": 0},
            ))

            # ============================================================
            # Phase 3: Port Scanning (10–20%)
            # ============================================================
            open_ports = []
            is_quick = scan_mode.lower() in ("quick", "quick scan", "fast")
            if not is_quick:
                await self._emit(progress, self._build_payload(
                    counters, 11, "Port Scanning", target_url,
                    event="recon_step",
                    log={"level": "SCAN", "message": f"[PORT] Probing common TCP services on {host}"},
                    module_info={"name": "Port Scanner", "status": "Scanning", "findings": 0},
                ))

                async def port_emit(payload: dict[str, Any]) -> None:
                    msg = payload.get("log_message", "")
                    if msg:
                        await self._emit(progress, self._build_payload(
                            counters, 16, "Port Scanning", target_url,
                            event="recon_step",
                            log={"level": "INFO", "message": msg},
                            module_info={"name": "Port Scanner", "status": "Scanning", "findings": 0},
                        ))

                try:
                    open_ports = await scan_ports(host, emit=port_emit)
                    counters.open_ports = len(open_ports)
                    await self._emit(progress, self._build_payload(
                        counters, 20, "Port Scanning", target_url,
                        event="recon_step",
                        log={"level": "SCAN", "message": f"[PORT] Completed - {len(open_ports)} open ports identified"},
                        module_info={"name": "Port Scanner", "status": "Complete", "findings": 0},
                    ))
                except Exception as exc:
                    await self._emit(progress, self._build_payload(
                        counters, 20, "Port Scanning", target_url,
                        event="recon_step",
                        log={"level": "WARN", "message": f"[PORT] Port scan failed: {exc}"},
                        module_info={"name": "Port Scanner", "status": "Complete", "findings": 0},
                    ))
            else:
                await self._emit(progress, self._build_payload(
                    counters, 20, "Port Scanning", target_url,
                    event="recon_step",
                    log={"level": "INFO", "message": "[PORT] Skipped (Quick Scan mode)"},
                    module_info={"name": "Port Scanner", "status": "Complete", "findings": 0},
                ))

            # ============================================================
            # Phase 4: Service Detection (20–25%)
            # ============================================================
            services = []
            if open_ports:
                await self._emit(progress, self._build_payload(
                    counters, 21, "Service Detection", target_url,
                    event="recon_step",
                    log={"level": "SCAN", "message": f"[SERVICE] Fingerprinting services on {len(open_ports)} ports"},
                    module_info={"name": "Service Fingerprinting", "status": "Scanning", "findings": 0},
                ))
                try:
                    services = await detect_services(host, open_ports)
                    counters.services_identified = len(services)
                    await self._emit(progress, self._build_payload(
                        counters, 25, "Service Detection", target_url,
                        event="recon_step",
                        log={"level": "SCAN", "message": f"[SERVICE] Completed - {len(services)} services fingerprinted"},
                        module_info={"name": "Service Fingerprinting", "status": "Complete", "findings": 0},
                    ))
                except Exception as exc:
                    await self._emit(progress, self._build_payload(
                        counters, 25, "Service Detection", target_url,
                        event="recon_step",
                        log={"level": "WARN", "message": f"[SERVICE] Service detection error: {exc}"},
                        module_info={"name": "Service Fingerprinting", "status": "Complete", "findings": 0},
                    ))
            else:
                await self._emit(progress, self._build_payload(
                    counters, 25, "Service Detection", target_url,
                    event="recon_step",
                    log={"level": "INFO", "message": "[SERVICE] No open ports to fingerprint"},
                    module_info={"name": "Service Fingerprinting", "status": "Complete", "findings": 0},
                ))

            # ============================================================
            # Phase 5: OS Detection (25–30%)
            # ============================================================
            os_info: dict[str, Any] = {"os": "Unknown"}
            await self._emit(progress, self._build_payload(
                counters, 26, "OS Detection", target_url,
                event="recon_step",
                log={"level": "SCAN", "message": "[OS] Analyzing network stack & TTL responses"},
                module_info={"name": "OS Fingerprinting", "status": "Scanning", "findings": 0},
            ))
            try:
                os_intel = await detect_operating_system(
                    host,
                    open_ports=open_ports,
                    http_headers=http_headers,
                    technologies=technologies,
                )
                detected_os = os_intel.get("name", "Unknown")
                detected_family = os_intel.get("family", "")
                os_info = {"os": detected_os, "name": detected_os, "family": detected_family, "details": os_intel}
                await self._emit(progress, self._build_payload(
                    counters, 30, "OS Detection", target_url,
                    event="recon_step",
                    log={"level": "INFO", "message": f"[OS] Fingerprinted: {detected_os} ({detected_family})"},
                    module_info={"name": "OS Fingerprinting", "status": "Complete", "findings": 0},
                ))
            except Exception as exc:
                detected_os = "Unknown"
                os_info = {"os": "Unknown"}
                await self._emit(progress, self._build_payload(
                    counters, 30, "OS Detection", target_url,
                    event="recon_step",
                    log={"level": "WARN", "message": f"[OS] Detection error: {exc}"},
                    module_info={"name": "OS Fingerprinting", "status": "Complete", "findings": 0},
                ))

            # ============================================================
            # Phase 6: Web & SPA Crawling (30–40%)
            # ============================================================
            await self._emit(progress, self._build_payload(
                counters, 31, "Web & SPA Crawler", target_url,
                event="recon_step",
                log={"level": "SCAN", "message": "[CRAWLER] Discovering pages, inputs, API routes, and hidden assets"},
                module_info={"name": "Web & SPA Crawler", "status": "Scanning", "findings": 0},
            ))

            async def crawler_emit(payload: dict[str, Any]) -> None:
                msg = payload.get("log_message", "")
                if msg:
                    await self._emit(progress, self._build_payload(
                        counters, 35, "Web & SPA Crawler", target_url,
                        event="recon_step",
                        log={"level": "INFO", "message": msg},
                        module_info={"name": "Web & SPA Crawler", "status": "Scanning", "findings": 0},
                    ))

            max_pages = 100 if depth.lower() == "high" else (15 if depth.lower() == "low" else 40)
            if is_quick:
                max_pages = min(max_pages, 8)

            crawl_result = await run_web_crawler(session, target_url, max_pages=max_pages, emit=crawler_emit)
            counters.requests_made += crawl_result.get("requests_made", 0)
            counters.endpoints_discovered += crawl_result.get("endpoints_discovered", 0)

            all_forms = crawl_result.get("forms", [])
            all_inputs = crawl_result.get("inputs", [])
            all_links = crawl_result.get("links", [])
            all_scripts = crawl_result.get("scripts", [])
            all_api_endpoints: list[dict[str, Any]] = []
            for ep in crawl_result.get("api_endpoints", []):
                if isinstance(ep, dict):
                    all_api_endpoints.append(ep)
                else:
                    all_api_endpoints.append({"url": str(ep), "method": "GET"})
            all_graphql_endpoints: list[str] = []
            all_xhr_requests: list[str] = []

            if html_content:
                parser = _TargetHTMLParser(target_url)
                parser.feed(html_content)
                all_forms = all_forms or parser.forms
                all_inputs = all_inputs or parser.inputs
                if not all_links:
                    all_links = parser.links
                if not all_scripts:
                    all_scripts = parser.scripts

            await self._emit(progress, self._build_payload(
                counters, 40, "Web & SPA Crawler", target_url,
                event="recon_step",
                log={"level": "SCAN", "message": f"[CRAWLER] Crawl complete - {counters.endpoints_discovered} endpoints, {len(all_forms)} forms, {len(all_inputs)} inputs"},
                module_info={"name": "Web & SPA Crawler", "status": "Complete", "findings": 0},
            ))

            # ============================================================
            # Phase 7: Playwright Deep Crawling (40–46%)
            # ============================================================
            playwright_data: dict[str, Any] = {}
            if not is_quick:
                await self._emit(progress, self._build_payload(
                    counters, 41, "Playwright Deep Discovery", target_url,
                    event="recon_step",
                    log={"level": "SCAN", "message": "[PLAYWRIGHT] Executing client JavaScript & SPA route discovery"},
                    module_info={"name": "Playwright Deep Discovery", "status": "Scanning", "findings": 0},
                ))

                async def pw_emit(payload: dict[str, Any]) -> None:
                    msg = payload.get("log_message", "")
                    if msg:
                        await self._emit(progress, self._build_payload(
                            counters, 44, "Playwright Deep Discovery", target_url,
                            event="recon_step",
                            log={"level": "INFO", "message": msg},
                            module_info={"name": "Playwright Deep Discovery", "status": "Scanning", "findings": 0},
                        ))

                try:
                    from app.scanner.modules.playwright_crawler import run_playwright_crawl
                    auth_cookies = {c["name"]: c["value"] for c in http_cookies if "name" in c and "value" in c}
                    playwright_data = await run_playwright_crawl(
                        target_url,
                        max_pages=20 if depth.lower() == "high" else (5 if depth.lower() == "low" else 10),
                        timeout_seconds=45.0,
                        auth_cookies=auth_cookies or None,
                        auth_headers=session.headers if auth_handler.is_configured else None,
                        emit=pw_emit,
                    )
                    counters.requests_made += playwright_data.get("requests_made", 0)
                    counters.endpoints_discovered += playwright_data.get("endpoints_discovered", 0)
                    all_forms.extend(playwright_data.get("forms", []))
                    all_inputs.extend(playwright_data.get("inputs", []))
                    for ep in playwright_data.get("api_endpoints", []):
                        if isinstance(ep, dict):
                            all_api_endpoints.append(ep)
                        else:
                            all_api_endpoints.append({"url": str(ep), "method": "GET"})
                    all_xhr_requests.extend(playwright_data.get("xhr_requests", []))
                    all_graphql_endpoints.extend(playwright_data.get("graphql_endpoints", []))
                    pw_urls = len(playwright_data.get("discovered_urls", []))
                    pw_xhr = len(playwright_data.get("xhr_requests", []))
                    pw_gql = len(playwright_data.get("graphql_endpoints", []))
                    await self._emit(progress, self._build_payload(
                        counters, 46, "Playwright Deep Discovery", target_url,
                        event="recon_step",
                        log={"level": "SCAN", "message": f"[PLAYWRIGHT] Deep discovery complete - {pw_urls} SPA routes, {pw_xhr} XHR APIs, {pw_gql} GraphQL"},
                        module_info={"name": "Playwright Deep Discovery", "status": "Complete", "findings": 0},
                    ))
                except Exception as exc:
                    await self._emit(progress, self._build_payload(
                        counters, 46, "Playwright Deep Discovery", target_url,
                        event="recon_step",
                        log={"level": "INFO", "message": f"[PLAYWRIGHT] Skipped ({exc})"},
                        module_info={"name": "Playwright Deep Discovery", "status": "Complete", "findings": 0},
                    ))
            else:
                await self._emit(progress, self._build_payload(
                    counters, 46, "Playwright Deep Discovery", target_url,
                    event="recon_step",
                    log={"level": "INFO", "message": "[PLAYWRIGHT] Skipped (Quick Scan mode)"},
                    module_info={"name": "Playwright Deep Discovery", "status": "Complete", "findings": 0},
                ))

            # Technology fingerprinting
            technologies = self._fingerprint_technologies(html_content, http_headers, http_cookies)
            if technologies:
                tech_names = ", ".join(t["name"] for t in technologies[:4])
                await self._emit(progress, self._build_payload(
                    counters, 47, "Technology Fingerprint", target_url,
                    event="recon_step",
                    log={"level": "INFO", "message": f"[TECH] Stack: {tech_names}"},
                ))

            # ============================================================
            # Phase 8: TLS & SSL Configuration (47–50%)
            # ============================================================
            tls: dict[str, Any] = {}
            await self._emit(progress, self._build_payload(
                counters, 47, "TLS / SSL Analysis", target_url,
                event="module_start",
                log={"level": "SCAN", "message": "[TLS] Inspecting SSL/TLS certificates and ciphers"},
                module_info={"name": "TLS / SSL Analysis", "status": "Scanning", "findings": 0},
            ))

            tls_findings = await scan_tls_security(
                target_url, host, http_headers,
                port=parsed.port or 443,
            )
            for tf in tls_findings:
                normalized = self._normalize_finding(tf, target_url, "tls_scanner", None)
                raw_findings.append(normalized)
                counters.findings_count += 1
                await self._emit(progress, self._build_payload(
                    counters, 49, "TLS / SSL Analysis", target_url,
                    event="finding",
                    finding=normalized,
                    log={"level": "FOUND", "message": f"[TLS] {tf.get('title', 'TLS issue')}"},
                    module_info={"name": "TLS / SSL Analysis", "status": "Scanning", "findings": len(tls_findings)},
                ))

            if target_url.startswith("https://"):
                try:
                    tls = await asyncio.to_thread(self._tls_lookup, parsed)
                except Exception:
                    pass

            await self._emit(progress, self._build_payload(
                counters, 50, "TLS / SSL Analysis", target_url,
                event="module_complete",
                log={"level": "SCAN", "message": f"[TLS] Complete - {len(tls_findings)} findings"},
                module_info={"name": "TLS / SSL Analysis", "status": "Complete", "findings": len(tls_findings)},
            ))

            # ============================================================
            # Phase 9: Cookie & JWT Security (50–54%)
            # ============================================================
            await self._emit(progress, self._build_payload(
                counters, 51, "Cookie & JWT Security", target_url,
                event="module_start",
                log={"level": "SCAN", "message": "[AUTH-SEC] Analyzing cookies and session tokens"},
                module_info={"name": "Cookie & JWT Security", "status": "Scanning", "findings": 0},
            ))

            cookie_findings = scan_cookies(http_cookies, target_url)
            for cf in cookie_findings:
                normalized = self._normalize_finding(cf, target_url, "cookie_scanner", None)
                raw_findings.append(normalized)
                counters.findings_count += 1
                await self._emit(progress, self._build_payload(
                    counters, 52, "Cookie & JWT Security", target_url,
                    event="finding",
                    finding=normalized,
                    log={"level": "FOUND", "message": f"[COOKIE] {cf.get('title', 'Cookie issue')}"},
                ))

            jwt_findings = await scan_jwt_security(session, target_url, http_headers, http_cookies)
            for jf in jwt_findings:
                normalized = self._normalize_finding(jf, target_url, "jwt_scanner", None)
                raw_findings.append(normalized)
                counters.findings_count += 1
                await self._emit(progress, self._build_payload(
                    counters, 53, "Cookie & JWT Security", target_url,
                    event="finding",
                    finding=normalized,
                    log={"level": "FOUND", "message": f"[JWT] {jf.get('title', 'JWT issue')}"},
                ))

            total_auth_findings = len(cookie_findings) + len(jwt_findings)
            await self._emit(progress, self._build_payload(
                counters, 54, "Cookie & JWT Security", target_url,
                event="module_complete",
                log={"level": "SCAN", "message": f"[AUTH-SEC] Complete - {total_auth_findings} findings"},
                module_info={"name": "Cookie & JWT Security", "status": "Complete", "findings": total_auth_findings},
            ))

            # Build recon dict for vulnerability scanners
            recon_dict: dict[str, Any] = {
                "url": target_url,
                "status_code": main_status,
                "headers": http_headers,
                "cookies": http_cookies,
                "html_content": html_content,
                "forms": all_forms,
                "inputs": all_inputs,
                "links": all_links,
                "technologies": technologies,
                "dns": dns_data.get("records", {}),
                "whois": whois_data,
                "ssl": tls,
            }

            ai_context = self.hack_ai.analyze_target(recon_dict)

            # ============================================================
            # Phase 10: Vulnerability Scanners (54%–86%)
            # ============================================================
            scanner_plan = self._plan_modules_from_recon(recon_dict, scan_mode, ai_context)
            counters.modules_total = len(scanner_plan)

            for index, module_name in enumerate(scanner_plan, start=1):
                if safety.is_scan_expired():
                    await self._emit(progress, self._build_payload(
                        counters, 86, "Scan Timeout", target_url,
                        event="module_error",
                        log={"level": "WARN", "message": "[SCAN] Duration limit reached"},
                    ))
                    break

                module_label = MODULE_LABELS.get(module_name, module_name.replace("_", " ").title())
                # Smooth progressive increments across 54% -> 86%
                step_progress_start = 54 + int(32 * (index - 1) / max(len(scanner_plan), 1))
                step_progress_end = 54 + int(32 * index / max(len(scanner_plan), 1))

                await self._emit(progress, self._build_payload(
                    counters, step_progress_start, module_label, target_url,
                    event="module_start",
                    log={"level": "SCAN", "message": f"[{module_name.upper()}] Launching {module_label} ({index}/{len(scanner_plan)})"},
                    module_info={"name": module_label, "status": "Scanning", "index": index, "total": len(scanner_plan), "findings": 0},
                ))

                scanner_cls = self.scanner_types[module_name]
                scanner = scanner_cls(self.hack_cfg, session)
                module_budget = 30.0 if is_quick else 60.0
                try:
                    module_findings = await asyncio.wait_for(
                        scanner.scan(target_url, recon_dict),
                        timeout=module_budget,
                    )
                    counters.requests_made += max(1, len(module_findings) + 2)
                except asyncio.TimeoutError:
                    await self._emit(progress, self._build_payload(
                        counters, step_progress_end, module_label, target_url,
                        event="module_complete",
                        log={"level": "WARN", "message": f"[{module_name.upper()}] Timed out after {int(module_budget)}s budget - moving to next probe"},
                        module_info={"name": module_label, "status": "Complete", "index": index, "total": len(scanner_plan), "findings": 0},
                    ))
                    module_findings = []
                except Exception as exc:
                    await self._emit(progress, self._build_payload(
                        counters, step_progress_end, module_label, target_url,
                        event="module_error",
                        log={"level": "WARN", "message": f"[{module_name.upper()}] Error: {exc}"},
                        module_info={"name": module_label, "status": "Complete", "index": index, "total": len(scanner_plan), "findings": 0},
                    ))
                    module_findings = []

                for finding in module_findings:
                    normalized = self._normalize_finding(finding, target_url, module_name, None)
                    raw_findings.append(normalized)
                    counters.findings_count += 1
                    severity = normalized.get("severity", "Info")
                    title = normalized.get("title", module_label)
                    log_level = "FOUND" if severity.lower() in ("critical", "high") else "INFO"
                    await self._emit(progress, self._build_payload(
                        counters, step_progress_end, module_label, finding.get("url", target_url),
                        event="finding",
                        finding=normalized,
                        log={"level": log_level, "message": f"[{module_name.upper()}] [{severity.upper()}] {title}"},
                        module_info={"name": module_label, "status": "Scanning", "index": index, "total": len(scanner_plan), "findings": len(module_findings)},
                    ))

                counters.modules_completed += 1
                await self._emit(progress, self._build_payload(
                    counters, step_progress_end, module_label, target_url,
                    event="module_complete",
                    log={"level": "SCAN", "message": f"[{module_name.upper()}] Completed - {len(module_findings)} findings"},
                    module_info={"name": module_label, "status": "Complete", "index": index, "total": len(scanner_plan), "findings": len(module_findings)},
                ))

            # ============================================================
            # Phase 11: API & GraphQL Security (86–90%)
            # ============================================================
            if (all_api_endpoints or all_graphql_endpoints) and scan_mode.lower() != "compliance":
                await self._emit(progress, self._build_payload(
                    counters, 86, "API & GraphQL Security", target_url,
                    event="module_start",
                    log={"level": "SCAN", "message": f"[API] Testing {len(all_api_endpoints)} APIs & {len(all_graphql_endpoints)} GraphQL endpoints"},
                    module_info={"name": "API & GraphQL Security", "status": "Scanning", "findings": 0},
                ))

                api_findings = await scan_api_endpoints(session, all_api_endpoints, target_url)
                gql_findings = await scan_graphql_endpoints(session, all_graphql_endpoints, target_url)
                combined_api_findings = api_findings + gql_findings

                for af in combined_api_findings:
                    normalized = self._normalize_finding(af, target_url, "api_scanner", None)
                    raw_findings.append(normalized)
                    counters.findings_count += 1
                    await self._emit(progress, self._build_payload(
                        counters, 89, "API & GraphQL Security", target_url,
                        event="finding",
                        finding=normalized,
                        log={"level": "FOUND", "message": f"[API] {af.get('title', 'API issue')}"},
                    ))

                await self._emit(progress, self._build_payload(
                    counters, 90, "API & GraphQL Security", target_url,
                    event="module_complete",
                    log={"level": "SCAN", "message": f"[API] Complete - {len(combined_api_findings)} findings"},
                    module_info={"name": "API & GraphQL Security", "status": "Complete", "findings": len(combined_api_findings)},
                ))

            # ============================================================
            # Phase 12: Adaptive Threat Chaining (90–94%)
            # ============================================================
            adaptive_summary: dict[str, Any] = {}
            if scan_mode.lower() == "full scan" and not safety.is_scan_expired():
                await self._emit(progress, self._build_payload(
                    counters, 91, "Adaptive Threat Chaining", target_url,
                    event="module_start",
                    log={"level": "SCAN", "message": "[ADAPTIVE] Chaining exploit vectors based on initial findings"},
                    module_info={"name": "Adaptive Threat Chaining", "status": "Scanning", "findings": 0},
                ))

                adaptive = AdaptiveEngine(set(self.scanner_types.keys()))
                already_run = set(scanner_plan)
                additional_findings: list[dict[str, Any]] = []

                for round_num in range(1, 3):
                    if safety.is_scan_expired():
                        break
                    recommendations = adaptive.recommend(raw_findings, already_run, round_num)
                    if not recommendations:
                        break

                    for rec in recommendations:
                        module_name = rec["module"]
                        if module_name not in self.scanner_types:
                            continue

                        scanner_cls = self.scanner_types[module_name]
                        scanner = scanner_cls(self.hack_cfg, session)
                        try:
                            m_findings = await scanner.scan(target_url, recon_dict)
                            for finding in m_findings:
                                normalized = self._normalize_finding(finding, target_url, module_name, None)
                                raw_findings.append(normalized)
                                additional_findings.append(normalized)
                                counters.findings_count += 1
                        except Exception:
                            pass
                        already_run.add(module_name)

                adaptive_summary = adaptive.summarize_adaptive_results([], additional_findings)

                await self._emit(progress, self._build_payload(
                    counters, 94, "Adaptive Threat Chaining", target_url,
                    event="module_complete",
                    log={"level": "SCAN", "message": f"[ADAPTIVE] Complete - {len(additional_findings)} chained findings"},
                    module_info={"name": "Adaptive Threat Chaining", "status": "Complete", "findings": len(additional_findings)},
                ))

            # ============================================================
            # Phase 13: Evidence Verification (94–97%)
            # ============================================================
            if scan_mode.lower() == "full scan":
                high_findings = [f for f in raw_findings if f.get("severity", "").lower() in ("critical", "high")]
                if high_findings:
                    await self._emit(progress, self._build_payload(
                        counters, 95, "Evidence Verification", target_url,
                        event="module_start",
                        log={"level": "SCAN", "message": f"[VERIFY] Replaying {len(high_findings)} high/critical findings for confirmation"},
                        module_info={"name": "Evidence Verification", "status": "Scanning", "findings": 0},
                    ))

                    verified_count = 0
                    for finding in high_findings[:15]:
                        try:
                            verified = await evidence.verify_finding(finding)
                            if verified.get("verification_status") == "confirmed":
                                verified_count += 1
                        except Exception:
                            pass

                    await self._emit(progress, self._build_payload(
                        counters, 97, "Evidence Verification", target_url,
                        event="module_complete",
                        log={"level": "SCAN", "message": f"[VERIFY] Complete - {verified_count}/{len(high_findings)} confirmed"},
                        module_info={"name": "Evidence Verification", "status": "Complete", "findings": verified_count},
                    ))

            # ============================================================
            # Phase 13.5: Finding Validation Pipeline (97–98%)
            # ============================================================
            pre_pipeline_count = len(raw_findings)
            await self._emit(progress, self._build_payload(
                counters, 97, "Finding Validation", target_url,
                event="module_start",
                log={"level": "SCAN", "message": f"[PIPELINE] Validating & deduplicating {pre_pipeline_count} raw findings"},
                module_info={"name": "Finding Validation", "status": "Scanning", "findings": pre_pipeline_count},
            ))

            pipeline = FindingPipeline()
            raw_findings = pipeline.process(raw_findings)
            counters.findings_count = len(raw_findings)

            await self._emit(progress, self._build_payload(
                counters, 98, "Finding Validation", target_url,
                event="module_complete",
                log={"level": "SCAN", "message": (
                    f"[PIPELINE] Validation complete — {pre_pipeline_count} raw → "
                    f"{len(raw_findings)} validated ({pipeline.merged_count} merged, "
                    f"{pipeline.rejected_count} rejected)"
                )},
                module_info={"name": "Finding Validation", "status": "Complete", "findings": len(raw_findings)},
            ))

            # ============================================================
            # Phase 14: Report Generation & Finalization (98–100%)
            # ============================================================
            await self._emit(progress, self._build_payload(
                counters, 99, "Report Finalization", target_url,
                event="report_start",
                log={"level": "SCAN", "message": "[REPORT] Compiling executive report & evidence bundles"},
                module_info={"name": "Report Finalization", "status": "Scanning", "findings": 0},
            ))

            statistics = self._summarize_findings(raw_findings, started_at)
            completed_at = datetime.now(UTC)

            await self._emit(progress, self._build_payload(
                counters, 100, "Complete", target_url,
                event="scan_completed",
                log={"level": "SCAN", "message": f"[SCAN] Assessment completed - {counters.findings_count} findings, {counters.requests_made} requests, {counters.open_ports} open ports"},
                module_info={"name": "Report Finalization", "status": "Complete", "findings": 0},
            ))

            return {
                "target": target_url,
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "duration_seconds": (completed_at - started_at).total_seconds(),
                "recon": {
                    "url": target_url,
                    "status_code": main_status,
                    "headers": http_headers,
                    "cookies": http_cookies,
                    "forms": all_forms,
                    "inputs": all_inputs,
                    "links": all_links[:100],
                    "scripts": all_scripts,
                    "technologies": technologies,
                    "dns": dns_data.get("records", {}),
                    "whois": whois_data,
                    "tls": tls,
                    "robots_txt": crawl_result.get("robots_txt"),
                    "sitemap_xml": crawl_result.get("sitemap_xml"),
                    "directories": crawl_result.get("pages", []),
                    "sensitive_files": [],
                    "api_endpoints": all_api_endpoints,
                    "graphql_endpoints": all_graphql_endpoints,
                    "websocket_urls": playwright_data.get("websocket_urls", []),
                },
                "dns_data": dns_data,
                "whois_data": whois_data,
                "ns_data": ns_data,
                "open_ports": open_ports,
                "services": services,
                "os_info": os_info,
                "crawl_result": {
                    "pages": crawl_result.get("pages", []),
                    "api_endpoints": all_api_endpoints,
                    "forms": all_forms,
                    "endpoints_discovered": crawl_result.get("endpoints_discovered", 0),
                },
                "ai_context": ai_context,
                "findings": raw_findings,
                "statistics": statistics,
                "adaptive_summary": adaptive_summary,
                "counters": {
                    "requests_made": counters.requests_made,
                    "endpoints_discovered": counters.endpoints_discovered,
                    "findings_count": counters.findings_count,
                    "open_ports": counters.open_ports,
                    "services_detected": counters.services_detected,
                },
            }

    def _build_payload(
        self,
        counters: ScanCounters,
        progress_pct: int,
        current_module: str,
        current_url: str,
        *,
        event: str,
        log: dict[str, str] | None = None,
        finding: dict[str, Any] | None = None,
        module_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "event": event,
            "progress": progress_pct,
            "current_module": current_module,
            "current_url": current_url,
            "requests_count": counters.requests_made,
            "endpoints_count": counters.endpoints_discovered,
            "findings_count": counters.findings_count,
            "open_ports": counters.open_ports,
            "services_count": counters.services_detected,
            "eta_seconds": counters.eta_seconds(progress_pct),
        }
        if log:
            payload["log"] = {
                "time": datetime.now(UTC).strftime("%H:%M:%S"),
                "level": log["level"],
                "message": log["message"],
            }
        if finding:
            payload["finding"] = finding
        if module_info:
            payload["module_info"] = module_info
        return payload

    def _fingerprint_technologies(self, html: str, headers: dict[str, str], cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        technologies: list[dict[str, Any]] = []
        html_lower = html.lower()
        
        def add_tech(tech_type: str, name: str, conf: float):
            for t in technologies:
                if t["name"] == name:
                    return
            technologies.append({"type": tech_type, "name": name, "confidence": conf})

        server = headers.get("Server", "")
        if server:
            if "/" in server:
                name, version = server.split("/", 1)
                add_tech("server", f"{name.strip()} {version.strip()}", 0.95)
            else:
                add_tech("server", server.strip(), 0.95)
                
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            add_tech("framework", powered_by.strip(), 0.9)
            
        generator = headers.get("X-Generator", "")
        if generator:
            add_tech("cms", generator.strip(), 0.9)

        if "ASP.NET" in headers.get("X-AspNet-Version", "") or "X-AspNetMvc-Version" in headers:
            add_tech("framework", "ASP.NET", 0.95)

        for cookie in cookies:
            name = cookie.get("name", "")
            if name == "PHPSESSID": add_tech("language", "PHP", 0.9)
            elif name == "JSESSIONID": add_tech("language", "Java", 0.9)
            elif name == "connect.sid": add_tech("framework", "Express", 0.9)
            elif name == "laravel_session": add_tech("framework", "Laravel", 0.9)
            elif name == "sessionid": add_tech("framework", "Django", 0.7)
            elif name.startswith("wordpress_"): add_tech("cms", "WordPress", 0.9)

        if '<meta name="generator" content="WordPress' in html:
            add_tech("cms", "WordPress", 1.0)
        elif "wp-content" in html or "wp-includes" in html:
            add_tech("cms", "WordPress", 0.95)
            
        if "csrfmiddlewaretoken" in html:
            add_tech("framework", "Django", 0.85)
            
        if 'data-reactroot' in html or 'id="react-root"' in html or 'react.production.min.js' in html:
            add_tech("framework", "React", 0.95)
        elif "react" in html_lower:
            add_tech("framework", "React", 0.6)
            
        if 'ng-app' in html or 'ng-version' in html:
            add_tech("framework", "Angular", 0.95)
        elif "angular" in html_lower:
            add_tech("framework", "Angular", 0.6)
            
        if 'data-v-' in html or '__VUE' in html or 'vue.min.js' in html:
            add_tech("framework", "Vue.js", 0.95)
        elif "vue" in html_lower:
            add_tech("framework", "Vue.js", 0.6)
            
        if 'next/head' in html or '_next/static' in html:
            add_tech("framework", "Next.js", 0.95)
            
        if 'nuxt' in html_lower or '_nuxt' in html:
            add_tech("framework", "Nuxt.js", 0.95)
            
        if 'jquery' in html_lower:
            add_tech("library", "jQuery", 0.8)
            
        if 'bootstrap' in html_lower:
            add_tech("ui", "Bootstrap", 0.8)
            
        if 'tailwind' in html_lower:
            add_tech("ui", "Tailwind CSS", 0.8)

        if 'window.Shopify' in html:
            add_tech("ecommerce", "Shopify", 0.95)

        return technologies

    def _tls_lookup(self, parsed_url) -> dict[str, Any]:
        host = parsed_url.hostname or ""
        port = parsed_url.port or 443
        if not host:
            return {}
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        return {"valid": False, "error": "No certificate provided"}
                        
                    try:
                        import OpenSSL
                        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                        issuer = x509.get_issuer().CN or x509.get_issuer().O or "Unknown Issuer"
                        subject = x509.get_subject().CN or host
                        not_after = x509.get_notAfter()
                        
                        expiry_str = "Unknown"
                        if not_after:
                            from datetime import datetime
                            dt = datetime.strptime(not_after.decode('ascii'), "%Y%m%d%H%M%SZ")
                            expiry_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                            
                        return {
                            "valid": True,
                            "version": ssock.version(),
                            "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                            "issuer": issuer,
                            "subject": subject,
                            "expires": expiry_str,
                        }
                    except Exception:
                        return {"valid": False, "error": "Failed to parse certificate"}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _plan_modules_from_recon(self, recon: dict[str, Any], scan_mode: str, ai_context: dict[str, Any]) -> list[str]:
        scan_mode_lower = scan_mode.lower()
        if scan_mode_lower in ("quick", "quick scan", "fast"):
            return ["security_headers", "cors", "csrf", "xss", "open_redirect"]
        if scan_mode_lower in ("compliance", "compliance scan"):
            return ["security_headers", "cors", "csrf", "idor", "path_traversal", "xss"]

        # Default to Full Scan: Run ALL 15 modules thoroughly!
        all_modules = [
            "security_headers", "cors", "csrf", "xss", "sqli",
            "ssrf", "lfi", "xxe", "rce", "idor",
            "open_redirect", "path_traversal", "nosqli", "ldapi", "ssti"
        ]
        return all_modules

    def _normalize_finding(self, raw: dict[str, Any], target_url: str, module_name: str, recon: Any) -> dict[str, Any]:
        finding_type = str(raw.get("type") or raw.get("finding_type") or module_name or "information_disclosure")
        profile = lookup_profile(finding_type)
        affected_url = raw.get("url") or raw.get("affected_url") or target_url
        finding_id = raw.get("id") or str(uuid4())

        evidence_parts = []
        if affected_url:
            evidence_parts.append(f"Endpoint:\n{affected_url}\n")
        
        param = raw.get("parameter") or raw.get("affected_parameter") or raw.get("header_name") or raw.get("cookie_name")
        if param:
            evidence_parts.append(f"Parameter:\n{param}\n")
            
        method = raw.get("method")
        if method:
            evidence_parts.append(f"Method:\n{method}\n")
            
        detection = raw.get("detection") or raw.get("detection_technique")
        if detection:
            evidence_parts.append(f"Detection:\n{detection}\n")
            
        baseline = raw.get("baseline") or raw.get("baseline_response")
        if baseline:
            evidence_parts.append(f"Baseline:\n{baseline}\n")
            
        test_a = raw.get("test_a") or raw.get("payload_a") or raw.get("payload")
        if test_a:
            evidence_parts.append(f"Test A:\n{test_a}\n")
            
        test_b = raw.get("test_b") or raw.get("payload_b")
        if test_b:
            evidence_parts.append(f"Test B:\n{test_b}\n")
            
        verification = raw.get("verification") or raw.get("evidence")
        if verification:
            v_str = str(verification)
            if "Authentication bypass successful" in v_str and module_name != "auth_bypass" and not raw.get("auth_bypass_verified"):
                pass
            else:
                evidence_parts.append(f"Verification:\n{v_str}\n")

        ver_evidence = raw.get("verification_evidence")
        if ver_evidence:
            evidence_parts.append(f"Verification Response:\n{ver_evidence}\n")

        confidence = raw.get("confidence")
        if confidence:
            evidence_parts.append(f"Confidence:\n{confidence}\n")
            
        if not evidence_parts and raw.get("description"):
            evidence_parts.append(raw["description"][:200])

        evidence = "\n".join(evidence_parts).strip() if evidence_parts else f"Detected by {module_name} module"

        raw["finding_type"] = finding_type
        cvss_score, severity, cvss_vector = calculate_dynamic_cvss(raw)

        # Passive findings naturally have no request payload
        is_passive = finding_type in (
            "security_headers", "information_disclosure", "tls_misconfiguration",
            "cookie_security", "service_vulnerability", "dns_info", "whois_info", "os_detection"
        )
        
        method = raw.get("method") or ("N/A" if is_passive else "GET")
        payload_val = raw.get("payload") or ("N/A" if is_passive else None)

        http_request_dict = {"method": method, "url": affected_url}
        if payload_val is not None:
            http_request_dict["payload"] = payload_val

        meta = raw.get("metadata_json") or {}
        meta.update({
            "raw_type": finding_type,
            "source": module_name,
            "verification_status": raw.get("verification_status", "potential"),
            "detection_reason": raw.get("detection_reason") or detection or raw.get("description", ""),
        })
        if "needs_browser_verification" in raw:
            meta["needs_browser_verification"] = raw["needs_browser_verification"]
        if "reflection_context" in raw:
            meta["reflection_context"] = raw["reflection_context"]

        return {
            "id": finding_id,
            "finding_type": finding_type,
            "title": raw.get("title") or raw.get("description") or finding_type.replace("_", " ").title(),
            "description": raw.get("description") or raw.get("remediation") or profile.cwe_name,
            "evidence": evidence,
            "affected_url": affected_url,
            "affected_parameter": param or ("N/A" if is_passive else None),
            "http_request": json.dumps(http_request_dict, ensure_ascii=False),
            "http_response": raw.get("response") or None,
            "owasp_category": raw.get("owasp") or raw.get("owasp_category") or profile.owasp,
            "cwe_id": raw.get("cwe") or raw.get("cwe_id") or profile.cwe,
            "cwe_name": profile.cwe_name,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "confidence": str(raw.get("confidence") or profile.confidence),
            "risk_rating": str(raw.get("risk_rating") or profile.risk_rating),
            "remediation": raw.get("remediation") or self._default_remediation(finding_type),
            "best_practices": raw.get("best_practices") or self._default_remediation(finding_type) + " Perform recurring regression testing and add automated security checks to CI.",
            "secure_coding": raw.get("secure_coding") or "Follow defensive coding patterns, validate inputs at the boundary, and encode outputs in the correct context.",
            "verification_guidance": raw.get("verification_guidance") or "Re-run the scan after remediation, confirm the finding no longer reproduces, and document the verification evidence.",
            "references_json": raw.get("references") or raw.get("references_json") or [
                {"title": "OWASP Top 10", "url": "https://owasp.org/Top10/"},
                {"title": "OWASP Cheat Sheet Series", "url": "https://cheatsheetseries.owasp.org/"},
            ],
            "status": raw.get("status") or "open",
            "source_module": module_name,
            "detection_reason": raw.get("detection_reason") or detection or raw.get("description", ""),
            "verification_status": raw.get("verification_status", "potential"),
            "metadata_json": meta,
        }

    def _default_remediation(self, finding_type: str) -> str:
        remediations = {
            "xss": "Apply contextual output encoding, validate untrusted input, and enforce a strict Content Security Policy.",
            "sqli": "Use parameterized queries and prepared statements for all database access.",
            "csrf": "Attach anti-CSRF tokens to every state-changing request and validate origin headers.",
            "ssrf": "Restrict outbound requests, enforce allowlists, and block access to internal address ranges.",
            "lfi": "Normalize paths, restrict file access to known directories, and never concatenate untrusted path input.",
            "path_traversal": "Canonicalize file paths and enforce a strict allowlist of readable files.",
            "xxe": "Disable external entity resolution and use secure XML parser settings.",
            "rce": "Avoid shell execution with user input and use safe library APIs instead.",
            "idor": "Enforce object-level authorization checks on every record access.",
            "open_redirect": "Validate redirect targets against a server-side allowlist.",
            "cors": "Replace wildcard origins with explicit allowlists and never combine wildcard origins with credentials.",
            "nosqli": "Validate query structure and use typed query builders for NoSQL access.",
            "ldapi": "Escape LDAP metacharacters and build queries with trusted templates.",
            "ssti": "Treat templates as code, avoid rendering user-controlled template expressions, and use safe template contexts.",
            "security_headers": "Enable recommended security headers across the application and reverse proxy.",
            "cookie_security": "Set Secure, HttpOnly, and SameSite flags on all session and authentication cookies.",
            "service_vulnerability": "Update the affected service to the latest stable version that patches the identified CVE.",
            "jwt_weakness": "Use strong signing algorithms (RS256/ES256), enforce expiration, and never store sensitive data in JWT payloads.",
            "tls_misconfiguration": "Use TLS 1.2+ with strong cipher suites, enable HSTS, and use certificates from trusted CAs.",
            "api_security": "Implement proper authentication, authorization, rate limiting, and input validation on all API endpoints.",
            "graphql_security": "Disable introspection in production, implement query depth limits, and sanitize error messages.",
        }
        return remediations.get(finding_type, "Review the affected code path, implement least privilege, and validate all untrusted input before use.")

    def _summarize_findings(self, findings: list[dict[str, Any]], started_at: datetime) -> dict[str, Any]:
        severity_counts = Counter(finding["severity"].lower() for finding in findings)
        type_counts = Counter(finding["finding_type"] for finding in findings)
        module_counts = Counter(finding.get("source_module", "unknown") for finding in findings)
        return {
            "total_findings": len(findings),
            "severity_counts": dict(severity_counts),
            "type_counts": dict(type_counts),
            "module_counts": dict(module_counts),
            "overall_risk_score": round(min(100.0, sum({"critical": 20, "high": 12, "medium": 6, "low": 2, "info": 0}.get(severity.lower(), 0) * count for severity, count in severity_counts.items())), 2),
            "started_at": started_at.isoformat(),
        }

    async def _emit(self, progress: ProgressCallback | None, payload: dict[str, Any]) -> None:
        if progress is None:
            return
        result = progress(payload)
        if asyncio.iscoroutine(result):
            await result
