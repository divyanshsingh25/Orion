# ORION SECURITY CHECK & SCAN PIPELINE AUDIT REPORT
**Document Version:** 1.0.0  
**Audit Date:** September 22, 2026  
**Auditor:** Antigravity AI Codebase Auditor  
**Repository:** Orion Security Assessment Platform  
**Target Codebase:** `backend/app/` and `hacktheweb-main/hacktheweb/`

---

## 1. EXECUTIVE SUMMARY

An exhaustive, line-by-line audit of the Orion security assessment engine was conducted to trace the complete scan execution path from initial user input to final PDF report generation. Every scanner module, detector, crawler, parser, and pipeline quality gate was inspected directly in the code without assumptions or simulated behavior.

### Key Audit Findings:
1. **Core Vulnerability Detection Engine (HackTheWeb):** Orion integrates the HackTheWeb scanning suite via `backend/app/scanner/hacktheweb_adapter.py` and `backend/app/scanner/orchestrator.py`. All 15 core web vulnerability scanners (`security_headers`, `csrf`, `cors`, `xss`, `sqli`, `ssrf`, `lfi`, `xxe`, `rce`, `idor`, `open_redirect`, `path_traversal`, `nosqli`, `ldapi`, `ssti`) are **fully implemented and executed** in Full Scan mode (5 executed in Quick Scan mode).
2. **Modern Specialized Scanners:** Orion features dedicated native modules for TLS Security (`tls_scanner.py`), Cookie Security (`cookie_scanner.py`), JWT Token Analysis (`jwt_scanner.py`), REST API Security (`api_scanner.py`), and GraphQL Security (`graphql_scanner.py`), all of which are **fully implemented and executed**.
3. **Reconnaissance & Discovery:** Real DNS record enumeration and dictionary subdomain brute-forcing (`dns_enumerator.py`), WHOIS registration lookup (`whois_lookup.py`), Name Server resolution (`ns_lookup.py`), and HTTP web crawling (`web_crawler.py`) are **fully implemented and executed**. Browser-based SPA/DOM crawling (`playwright_crawler.py`) is implemented and executed conditionally when Playwright and system subprocess dependencies are present.
4. **Execution Discrepancies (Implemented But Not Executed):**
   - **Port Scanning (`port_scanner.py`):** The module is implemented, but `orchestrator.py` calls `scan_ports()` instead of the imported `run_port_scan()`, causing a caught `NameError`.
   - **Service Detection (`service_detector.py`):** Conditioned on open ports; also exhibits a function signature mismatch in `orchestrator.py`.
   - **OS Fingerprinting (`os_detector.py`):** Implemented, but `orchestrator.py` calls `detect_operating_system()` instead of the imported `detect_os()`, causing a caught `NameError`.
   - **CVE Lookup (`cve_lookup.py`):** Implemented in `modules/cve_lookup.py` and imported in `orchestrator.py`, but never called in the scan workflow.
   - **Legacy TLS Analyzer (`tls_analyzer.py`):** Redundant legacy file superseded by `tls_scanner.py`; never imported or executed.
5. **Quality Gates & Post-Processing:**
   - **Adaptive Threat Chaining (`adaptive_engine.py`):** Executed in Full Scan mode to evaluate finding relationships.
   - **Active Evidence Verification (`evidence_collector.py`):** Executed in Full Scan mode to replay up to 15 High/Critical findings.
   - **Validation & Deduplication Pipeline (`finding_pipeline.py`):** Executed on all raw findings to enforce evidence criteria and deduplicate via SHA256 root-cause correlation keys.
   - **AI Verification & Analysis (`AIService`, `AIVerifier`):** Executed upon persistence to enrich findings with remediation, code fixes, and confidence scoring.

---

## 2. COMPLETE SCAN LIFECYCLE (END-TO-END FLOW)

The complete execution lifecycle traces through 16 distinct operational stages:

```
[User Input] Target URL & Scan Options (Frontend Dashboard/Modal)
    │
    ▼
[API Request] POST /api/v1/scans (FastAPI: app/api/v1/scans.py)
    │
    ▼
[Scan Creation] Target validation, Scan record created in DB (status="queued")
    │           (app/services/scan_service.py:create_scan)
    ▼
[Task Orchestration] Fire-and-forget Celery task or asyncio background task
    │                 (app/services/scan_service.py:_run_scan_background)
    ▼
[Background Worker] ScanService.run_scan(scan_id) with isolated DB session
    │               Scan status updated to "running", progress=1%
    ▼
[Live Telemetry] Telemetry cache initialized, WebSocket broadcast "scan_started"
    │            (app/middleware/websocket_manager.py)
    ▼
[Safety Layer] ScanSafety initialized (rate limit, concurrency, scope, timeouts)
    │          (app/scanner/safety.py)
    ▼
[Session & Auth] aiohttp.ClientSession created, AuthHandler executes login if configured
    │            (app/scanner/auth_handler.py)
    ▼
[Reconnaissance & Discovery]
    ├── DNS & Subdomain Enumeration (app/scanner/modules/dns_enumerator.py)
    ├── WHOIS & NS Resolution (app/scanner/modules/whois_lookup.py, ns_lookup.py)
    ├── HTTP Web Crawling (app/scanner/modules/web_crawler.py: pages, forms, inputs, APIs)
    └── Playwright Deep SPA Discovery (app/scanner/modules/playwright_crawler.py)
    │
    ▼
[Target Baseline & Intelligence]
    ├── Technology Fingerprinting (app/scanner/orchestrator.py:_fingerprint_technologies)
    └── AI Target Context (hacktheweb/core/ai_engine.py:analyze_target)
    │
    ▼
[Security Posture & Configuration Testing]
    ├── TLS / SSL Configuration (app/scanner/modules/tls_scanner.py)
    ├── Cookie Security Flags (app/scanner/modules/cookie_scanner.py)
    ├── JWT Token Security (app/scanner/modules/jwt_scanner.py)
    ├── HTTP Security Headers (hacktheweb/scanners/security_headers_scanner.py)
    └── CORS Policy Analysis (hacktheweb/scanners/cors_scanner.py)
    │
    ▼
[Web Application Vulnerability Testing]
    ├── CSRF Protection (hacktheweb/scanners/csrf_scanner.py)
    ├── Cross-Site Scripting / XSS (hacktheweb/scanners/xss_scanner.py)
    ├── SQL Injection / SQLi (hacktheweb/scanners/sqli_scanner.py)
    ├── Server-Side Request Forgery / SSRF (hacktheweb/scanners/ssrf_scanner.py)
    ├── Local File Inclusion / LFI (hacktheweb/scanners/lfi_scanner.py)
    ├── XML External Entity / XXE (hacktheweb/scanners/xxe_scanner.py)
    ├── Remote Code Execution / RCE (hacktheweb/scanners/rce_scanner.py)
    ├── Broken Access Control / IDOR (hacktheweb/scanners/idor_scanner.py)
    ├── Open URL Redirection (hacktheweb/scanners/open_redirect_scanner.py)
    ├── Path Traversal (hacktheweb/scanners/path_traversal_scanner.py)
    ├── NoSQL Injection (hacktheweb/scanners/nosqli_scanner.py)
    ├── LDAP Injection (hacktheweb/scanners/ldapi_scanner.py)
    └── Server-Side Template Injection / SSTI (hacktheweb/scanners/ssti_scanner.py)
    │
    ▼
[API & Service Security Testing]
    ├── REST API Security & Method Enumeration (app/scanner/modules/api_scanner.py)
    └── GraphQL Security Testing (app/scanner/modules/graphql_scanner.py)
    │
    ▼
[Post-Scan Quality Gates]
    ├── Adaptive Threat Chaining (app/scanner/adaptive_engine.py)
    ├── Active Evidence Verification (app/scanner/evidence_collector.py)
    └── Finding Validation & Deduplication Pipeline (app/scanner/finding_pipeline.py)
    │
    ▼
[Finding Normalization & Classification]
    ├── Dynamic CVSS v3.1 Scoring & OWASP/CWE Mapping (app/core/owasp.py)
    ├── Database Persistence: Finding & AIAnalysis models (app/services/scan_service.py)
    └── Non-blocking Async AI Verification (app/services/ai_verifier.py)
    │
    ▼
[Scan Completion & Reporting]
    ├── Target risk score update & statistics finalization
    ├── WebSocket broadcast "scan_completed"
    └── Automatic PDF Report Generation (app/reports/generator.py & builder.py)
```

---

## 3. ACTUAL SCAN EXECUTION ORDER

Based strictly on `OrionScanner.scan()` in `backend/app/scanner/orchestrator.py`:

| Step # | Progress % | Pipeline Stage | Source Module | Execution Type |
|---|---|---|---|---|
| **01** | 1% | Scan Initialization & Target Validation | `orchestrator.py` | Synchronous Validation |
| **02** | 2–3% | Target Authentication (if configured) | `auth_handler.py` | Active HTTP Form/Header |
| **03** | 3% | Initial Baseline HTTP Request | `orchestrator.py` | Active HTTP GET |
| **04** | 3–6% | DNS Enumeration & Subdomain Discovery | `modules/dns_enumerator.py` | DNS Queries (UDP/TCP 53) |
| **05** | 6–10% | WHOIS Registry & Name Server Lookup | `modules/whois_lookup.py`, `ns_lookup.py` | WHOIS Port 43 & DNS |
| **06** | 10–20% | Port Scanning | `modules/port_scanner.py` | *Encountered NameError (Skipped)* |
| **07** | 20–25% | Service Fingerprinting | `modules/service_detector.py` | *Skipped (No open ports)* |
| **08** | 25–30% | OS Fingerprinting | `modules/os_detector.py` | *Encountered NameError (Skipped)* |
| **09** | 30–40% | Web & SPA Crawling (robots, sitemap, links, forms) | `modules/web_crawler.py` | Active HTTP GET / HTML Parsing |
| **10** | 40–46% | Playwright Deep Discovery (SPA, XHR, WebSockets) | `modules/playwright_crawler.py` | Headless Chromium (Conditional) |
| **11** | 46–47% | Technology Fingerprinting | `orchestrator.py:_fingerprint_technologies` | Passive Header/HTML Analysis |
| **12** | 47–50% | TLS / SSL Configuration & Certificate Analysis | `modules/tls_scanner.py` | Active TLS Handshake & Socket |
| **13** | 50–54% | Cookie Security & JWT Token Security | `modules/cookie_scanner.py`, `jwt_scanner.py` | Passive Flag + Offline HMAC Probe |
| **14** | 54–86% | Core Vulnerability Scanners (15 HackTheWeb modules) | `hacktheweb/scanners/*` | Active Payload Injection & Diffing |
| **15** | 86–90% | API & GraphQL Security Testing | `modules/api_scanner.py`, `graphql_scanner.py` | Active HTTP Requests & GraphQL |
| **16** | 90–94% | Adaptive Threat Chaining (Full mode only) | `adaptive_engine.py` | Algorithmic Evaluation |
| **17** | 94–97% | Active Evidence Verification (Full mode only) | `evidence_collector.py` | Active Request Replay |
| **18** | 97–98% | Finding Validation & Quality Pipeline | `finding_pipeline.py` | Algorithmic Dedup & SHA256 Keying |
| **19** | 98–100% | Severity Calculation, DB Persistence & PDF Report | `app/services/scan_service.py`, `app/reports/` | DB Write & ReportLab Build |

---

## 4. COMPLETE SECURITY CHECK INVENTORY

| # | Security Check | Category | Actually Executed | Source File | Finding Generated | Reported in PDF |
|---|---|---|---|---|---|---|
| 1 | DNS Record Resolution (A, AAAA, MX, NS, TXT, SOA) | Reconnaissance | **YES** | `modules/dns_enumerator.py` | No (Recon Data) | Yes (Target Details) |
| 2 | Subdomain Brute-Force Discovery | Reconnaissance | **YES** | `modules/dns_enumerator.py` | No (Recon Data) | Yes (Target Details) |
| 3 | WHOIS Domain Registration Lookup | Reconnaissance | **YES** | `modules/whois_lookup.py` | No (Recon Data) | Yes (Target Details) |
| 4 | Name Server IP Resolution | Reconnaissance | **YES** | `modules/ns_lookup.py` | No (Recon Data) | Yes (Target Details) |
| 5 | Web Crawling & Asset Enumeration | Attack Surface | **YES** | `modules/web_crawler.py` | No (Recon Data) | Yes (Endpoint Counts) |
| 6 | robots.txt & sitemap.xml Parsing | Attack Surface | **YES** | `modules/web_crawler.py` | No (Recon Data) | Yes (Recon Data) |
| 7 | Form & Input Parameter Extraction | Attack Surface | **YES** | `modules/web_crawler.py` | No (Recon Data) | Used by Scanners |
| 8 | Headless Browser SPA Discovery | Attack Surface | **YES (Optional)** | `modules/playwright_crawler.py` | No (Recon Data) | Used by Scanners |
| 9 | XHR / Fetch API Route Interception | Attack Surface | **YES (Optional)** | `modules/playwright_crawler.py` | No (Recon Data) | Used by Scanners |
| 10 | Technology Stack Fingerprinting | Reconnaissance | **YES** | `orchestrator.py` | No (Recon Data) | Yes (Exec Summary) |
| 11 | Plaintext HTTP Usage Detection | Network / TLS | **YES** | `modules/tls_scanner.py` | **YES** | **YES** |
| 12 | Deprecated TLS Protocol Detection | Network / TLS | **YES** | `modules/tls_scanner.py` | **YES** | **YES** |
| 13 | Weak TLS Cipher Suite Detection | Network / TLS | **YES** | `modules/tls_scanner.py` | **YES** | **YES** |
| 14 | Inadequate Encryption Key Length (<128-bit) | Network / TLS | **YES** | `modules/tls_scanner.py` | **YES** | **YES** |
| 15 | Certificate Expiration & Validity Checks | Network / TLS | **YES** | `modules/tls_scanner.py` | **YES** | **YES** |
| 16 | Self-Signed Certificate Detection | Network / TLS | **YES** | `modules/tls_scanner.py` | **YES** | **YES** |
| 17 | Cookie Secure Flag Verification | Web Application | **YES** | `modules/cookie_scanner.py` | **YES** | **YES** |
| 18 | Cookie HttpOnly Flag Verification | Web Application | **YES** | `modules/cookie_scanner.py` | **YES** | **YES** |
| 19 | Cookie SameSite Attribute Verification | Web Application | **YES** | `modules/cookie_scanner.py` | **YES** | **YES** |
| 20 | JWT 'none' Algorithm Acceptance | Authentication | **YES** | `modules/jwt_scanner.py` | **YES** | **YES** |
| 21 | Expired JWT Acceptance | Authentication | **YES** | `modules/jwt_scanner.py` | **YES** | **YES** |
| 22 | JWT Missing Expiration Claim | Authentication | **YES** | `modules/jwt_scanner.py` | **YES** | **YES** |
| 23 | JWT Missing Security Claims (iss, aud, iat) | Authentication | **YES** | `modules/jwt_scanner.py` | **YES** | **YES** |
| 24 | JWT Weak Signing Secret (HMAC Dictionary) | Authentication | **YES** | `modules/jwt_scanner.py` | **YES** | **YES** |
| 25 | JWT Sensitive Data Exposure in Payload | Authentication | **YES** | `modules/jwt_scanner.py` | **YES** | **YES** |
| 26 | Missing Content-Security-Policy (CSP) | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 27 | Weak Content-Security-Policy Directives | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 28 | Missing Strict-Transport-Security (HSTS) | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 29 | Misconfigured HSTS max-age Directive | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 30 | Missing X-Content-Type-Options Header | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 31 | Missing Clickjacking Protection (XFO/CSP) | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 32 | Missing Referrer-Policy Header | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 33 | Technology Header Disclosure (X-Powered-By) | Security Posture | **YES** | `security_headers_scanner.py` | **YES** | **YES** |
| 34 | CORS Arbitrary Origin Reflected + Credentials | Web Application | **YES** | `cors_scanner.py` | **YES** | **YES** |
| 35 | CORS Arbitrary Origin Reflected (No Creds) | Web Application | **YES** | `cors_scanner.py` | **YES** | **YES** |
| 36 | CORS Null Origin Allowed with Credentials | Web Application | **YES** | `cors_scanner.py` | **YES** | **YES** |
| 37 | CORS Wildcard Origin with Credentials | Web Application | **YES** | `cors_scanner.py` | **YES** | **YES** |
| 38 | CORS Permissive Wildcard Origin (*) | Web Application | **YES** | `cors_scanner.py` | **YES** | **YES** |
| 39 | CORS Preflight Allows Dangerous Methods | Web Application | **YES** | `cors_scanner.py` | **YES** | **YES** |
| 40 | Missing Anti-CSRF Tokens on Forms | Web Application | **YES** | `csrf_scanner.py` | **YES** | **YES** |
| 41 | Reflected Cross-Site Scripting (XSS) | Web Application | **YES** | `xss_scanner.py` | **YES** | **YES** |
| 42 | SQL Injection (Error-Based) | Web Application | **YES** | `sqli_scanner.py` | **YES** | **YES** |
| 43 | SQL Injection (Time-Based Blind) | Web Application | **YES** | `sqli_scanner.py` | **YES** | **YES** |
| 44 | SQL Injection (Boolean-Based) | Web Application | **YES** | `sqli_scanner.py` | **YES** | **YES** |
| 45 | SQL Injection (UNION-Based) | Web Application | **YES** | `sqli_scanner.py` | **YES** | **YES** |
| 46 | Server-Side Request Forgery (Cloud Metadata) | Web Application | **YES** | `ssrf_scanner.py` | **YES** | **YES** |
| 47 | Server-Side Request Forgery (Local Protocols) | Web Application | **YES** | `ssrf_scanner.py` | **YES** | **YES** |
| 48 | Local File Inclusion (LFI - Sensitive Files) | Web Application | **YES** | `lfi_scanner.py` | **YES** | **YES** |
| 49 | XML External Entity (XXE Injection) | Web Application | **YES** | `xxe_scanner.py` | **YES** | **YES** |
| 50 | OS Command Injection | Web Application | **YES** | `rce_scanner.py` | **YES** | **YES** |
| 51 | Remote Code Execution (Code Injection) | Web Application | **YES** | `rce_scanner.py` | **YES** | **YES** |
| 52 | Insecure Direct Object Reference (IDOR) | Web Application | **YES** | `idor_scanner.py` | **YES** | **YES** |
| 53 | Open URL Redirection | Web Application | **YES** | `open_redirect_scanner.py` | **YES** | **YES** |
| 54 | Path Traversal / Directory Traversal | Web Application | **YES** | `path_traversal_scanner.py` | **YES** | **YES** |
| 55 | NoSQL Injection (Operator & String Injection) | Web Application | **YES** | `nosqli_scanner.py` | **YES** | **YES** |
| 56 | LDAP Injection (Filter & Auth Bypass) | Web Application | **YES** | `ldapi_scanner.py` | **YES** | **YES** |
| 57 | Server-Side Template Injection (SSTI) | Web Application | **YES** | `ssti_scanner.py` | **YES** | **YES** |
| 58 | HTTP Method Enumeration & TRACE Check | API Security | **YES** | `modules/api_scanner.py` | **YES** | **YES** |
| 59 | API Excessive Data Exposure & PII Detection | API Security | **YES** | `modules/api_scanner.py` | **YES** | **YES** |
| 60 | API Unpaginated Large Data Response | API Security | **YES** | `modules/api_scanner.py` | **YES** | **YES** |
| 61 | API-Specific CORS Misconfiguration | API Security | **YES** | `modules/api_scanner.py` | **YES** | **YES** |
| 62 | GraphQL Introspection Query Enabled | API Security | **YES** | `modules/graphql_scanner.py` | **YES** | **YES** |
| 63 | GraphQL Missing Query Depth Limit / DoS | API Security | **YES** | `modules/graphql_scanner.py` | **YES** | **YES** |
| 64 | GraphQL Batch Query Abuse | API Security | **YES** | `modules/graphql_scanner.py` | **YES** | **YES** |
| 65 | GraphQL Information Disclosure via Errors | API Security | **YES** | `modules/graphql_scanner.py` | **YES** | **YES** |
| 66 | GraphQL Schema Leakage via Suggestions | API Security | **YES** | `modules/graphql_scanner.py` | **YES** | **YES** |
| 67 | TCP Port Scanning (`port_scanner.py`) | Reconnaissance | **NO** (NameError) | `modules/port_scanner.py` | No | No |
| 68 | Service Banner Fingerprinting (`service_detector.py`) | Reconnaissance | **NO** (Skipped) | `modules/service_detector.py` | No | No |
| 69 | OS Network Stack Fingerprinting (`os_detector.py`) | Reconnaissance | **NO** (NameError) | `modules/os_detector.py` | No | No |
| 70 | CVE Database Lookup (`cve_lookup.py`) | Vulnerability DB | **NO** (Uncalled) | `modules/cve_lookup.py` | No | No |
| 71 | Synchronous TLS Analyzer (`tls_analyzer.py`) | Network / TLS | **NO** (Unused) | `modules/tls_analyzer.py` | No | No |

---

## 5. DETAILED SPECIFICATION OF CONFIRMED SECURITY CHECKS

### A. Reconnaissance & Attack Surface Mapping

#### 1. DNS Record Enumeration
- **Check Name:** DNS Record Enumeration
- **Category:** Reconnaissance / Network Intelligence
- **Source File:** `backend/app/scanner/modules/dns_enumerator.py`
- **Class / Function:** `run_dns_enumeration(host)`
- **What it tests:** Queries authoritative nameservers for DNS record types (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`).
- **Input:** Target domain hostname.
- **Trigger:** Phase 1 of scan orchestrator.
- **Requests:** Standard DNS queries (UDP/TCP 53) via `dnspython`.
- **Condition for Finding:** Does not generate vulnerability findings; stores discovered records into `scan.recon_dns_json`.
- **Evidence:** Record values and TTLs.
- **Severity / CVSS / CWE / OWASP:** N/A (Reconnaissance data).
- **Execution Mode:** Passive network query (Non-destructive).

#### 2. Subdomain Brute-Force Discovery
- **Check Name:** Subdomain Dictionary Enumeration
- **Category:** Reconnaissance / Attack Surface Discovery
- **Source File:** `backend/app/scanner/modules/dns_enumerator.py`
- **Class / Function:** `_resolve_subdomain()` via `run_dns_enumeration()`
- **What it tests:** Tests 45 high-probability subdomain prefixes (`www`, `mail`, `api`, `dev`, `staging`, `admin`, `vpn`, `auth`, `portal`, etc.) against target domain.
- **Input:** Target hostname.
- **Trigger:** Phase 1 of scan orchestrator.
- **Requests:** Concurrent DNS A-record queries via `asyncio.gather`.
- **Condition for Finding:** Resolving subdomains are added to `scan.recon_dns_json['subdomains']`.
- **Evidence:** FQDN and resolved IPv4 addresses.
- **Severity / CVSS / CWE / OWASP:** N/A (Reconnaissance data).
- **Execution Mode:** Passive DNS resolution (Non-destructive).

#### 3. WHOIS Registry Lookup
- **Check Name:** WHOIS Domain Registration Intelligence
- **Category:** Reconnaissance / Network Intelligence
- **Source File:** `backend/app/scanner/modules/whois_lookup.py`
- **Class / Function:** `run_whois_lookup(host)`
- **What it tests:** Queries WHOIS database for registrar, creation/expiration dates, domain status, name servers, and registrant organization.
- **Input:** Target hostname.
- **Trigger:** Phase 2 of scan orchestrator.
- **Requests:** TCP port 43 WHOIS queries via `python-whois`.
- **Condition for Finding:** Stores registration metadata in `scan.recon_whois_json`.
- **Severity / CVSS / CWE / OWASP:** N/A (Reconnaissance data).
- **Execution Mode:** Passive registry query (Non-destructive).

#### 4. Web & SPA Application Crawling
- **Check Name:** Web Application Scope Crawler
- **Category:** Attack Surface Mapping
- **Source File:** `backend/app/scanner/modules/web_crawler.py`
- **Class / Function:** `run_web_crawler()`
- **What it tests:** Traverses target pages up to budget (`max_pages`: 8 in Quick, 15–100 in Full). Discovers `robots.txt`, `sitemap.xml`, internal HTML links, forms, input fields, script assets, and API routes.
- **Input:** Target URL, aiohttp session.
- **Trigger:** Phase 6 of scan orchestrator.
- **Requests:** HTTP GET requests strictly within origin scope.
- **Condition for Finding:** Discovered forms and URL parameters feed vulnerability scanners; page list saved to `scan.endpoints_json`.
- **Severity / CVSS / CWE / OWASP:** N/A (Attack Surface Mapping).
- **Execution Mode:** Safe HTTP crawling (Non-destructive).

#### 5. Headless Browser Deep Discovery (Playwright)
- **Check Name:** Headless Browser Client-Side Discovery
- **Category:** Attack Surface Mapping
- **Source File:** `backend/app/scanner/modules/playwright_crawler.py`
- **Class / Function:** `run_playwright_crawl()`
- **What it tests:** Launches headless Chromium to render JavaScript, discover SPA client-side routes, intercept background XHR/fetch traffic, detect WebSocket connections, and discover GraphQL endpoints.
- **Input:** Target URL, cookies, auth headers.
- **Trigger:** Phase 7 of scan orchestrator (Full scan mode only, conditional on Playwright availability).
- **Requests:** Browser navigation, synthetic element clicks, network interception.
- **Severity / CVSS / CWE / OWASP:** N/A (Attack Surface Mapping).
- **Execution Mode:** Client-side JavaScript execution (Non-destructive).

---

### B. Transport Layer & Network Security

#### 6. Transport Layer Security (TLS / SSL) Scanner
- **Check Name:** TLS/SSL Configuration & Certificate Assessment
- **Category:** TLS / Network Security
- **Source File:** `backend/app/scanner/modules/tls_scanner.py`
- **Class / Function:** `scan_tls_security()`, `_analyze_tls_sync()`
- **What it tests:**
  1. Plain HTTP target scheme without encryption (`CWE-319`, High, CVSS 7.5).
  2. TLS handshake failures / connection errors (`CWE-295`, High, CVSS 7.5).
  3. Deprecated protocol negotiation (TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0) (`CWE-326`, High, CVSS 7.5).
  4. Insecure cipher suites (`RC4`, `DES`, `3DES`, `NULL`, `EXPORT`, `MD5`, `RC2`, `IDEA`, `SEED`, `CAMELLIA`) (`CWE-326`, Medium, CVSS 5.3).
  5. Short encryption key length (< 128 bits) (`CWE-326`, Medium, CVSS 5.3).
  6. Expired TLS certificates (`CWE-295`, Critical, CVSS 9.1).
  7. Certificates expiring within 30 days (`CWE-295`, Low, CVSS 3.1).
  8. Self-signed certificate validation (`CWE-295`, Medium, CVSS 5.3).
- **Input:** Target URL, hostname, port (default 443).
- **Trigger:** Phase 8 of scan orchestrator.
- **Requests:** Raw SSL/TLS socket connections via Python `ssl` and `OpenSSL`.
- **Evidence:** Negotiated protocol, cipher suite name, bit length, certificate subject, issuer, and expiration date.
- **Remediation:** Enforce TLS 1.2+, modern cipher suites (AES-GCM/ChaCha20), and renew certificates via trusted CAs.
- **Execution Mode:** Active TLS handshake (Non-destructive).

---

### C. Security Posture & Configuration

#### 7. HTTP Security Headers Scanner
- **Check Name:** HTTP Security Headers & Disclosure Analyzer
- **Category:** Configuration / Security Posture
- **Source File:** `hacktheweb-main/hacktheweb/scanners/security_headers_scanner.py`
- **Class / Function:** `SecurityHeadersScanner.scan()`
- **What it tests:**
  1. **Content-Security-Policy (CSP):** Missing CSP (`CWE-693`, Low, CVSS 3.7) or weak directives (`unsafe-inline`, `unsafe-eval`) (`CWE-693`, Low, CVSS 3.1).
  2. **Strict-Transport-Security (HSTS):** Missing HSTS on HTTPS (`CWE-319`, Low, CVSS 3.7) or missing `max-age` (`CWE-319`, Low, CVSS 2.7).
  3. **X-Content-Type-Options:** Missing header (`CWE-693`, Low, CVSS 3.1) or value not `nosniff` (`CWE-693`, Low, CVSS 2.5).
  4. **Clickjacking Protection:** Missing both `X-Frame-Options` and CSP `frame-ancestors` (`CWE-1021`, Low, CVSS 3.7) or weak XFO (`CWE-1021`, Low, CVSS 2.7).
  5. **Referrer-Policy:** Missing header (`CWE-200`, Low, CVSS 2.5).
  6. **Server Banner / Technology Disclosure:** `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` disclosing backend frameworks (`CWE-200`, Low, CVSS 2.0).
- **Input:** Response headers from baseline request or target GET.
- **Trigger:** Phase 10 of scan orchestrator.
- **Requests:** Evaluates pre-fetched baseline headers or issues 1 HTTP GET request.
- **Evidence:** Missing header name, observed headers list, or disclosed framework string.
- **Remediation:** Configure reverse proxy/web server to emit recommended security headers and strip disclosure headers.
- **Execution Mode:** Passive header inspection (Non-destructive).

#### 8. Cross-Origin Resource Sharing (CORS) Scanner
- **Check Name:** CORS Policy & Origin Reflection Analyzer
- **Category:** Configuration / Web Application Security
- **Source File:** `hacktheweb-main/hacktheweb/scanners/cors_scanner.py`
- **Class / Function:** `CORSScanner.scan()`, `_test_cors()`, `_test_preflight()`
- **What it tests:**
  1. Reflected arbitrary Origin (`https://evil-attacker-probe.com`) with `Access-Control-Allow-Credentials: true` (`CWE-942`, High, CVSS 7.5).
  2. Reflected arbitrary Origin without credentials (`CWE-942`, Medium, CVSS 5.3).
  3. Null Origin (`Origin: null`) with credentials allowed (`CWE-942`, High, CVSS 7.5).
  4. Wildcard Origin (`*`) with credentials allowed (`CWE-942`, Medium, CVSS 5.3).
  5. Permissive Wildcard Origin (`*`) on public resource (`CWE-942`, Low, CVSS 3.0).
  6. CORS preflight OPTIONS request permitting dangerous state-changing methods (`PUT`, `DELETE`, `PATCH`) from arbitrary origin (`CWE-942`, Medium, CVSS 5.3).
- **Input:** Target URL and discovered API endpoints.
- **Trigger:** Phase 10 of scan orchestrator.
- **Requests:** HTTP GET with custom `Origin` headers; HTTP OPTIONS preflight request.
- **Evidence:** Request Origin, response `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, and allowed methods.
- **Remediation:** Maintain explicit server-side origin allowlists; never combine dynamic reflection or wildcards with credentials.
- **Execution Mode:** Active probe with synthetic origin headers (Non-destructive).

#### 9. Cookie Security Scanner
- **Check Name:** Cookie Security Flags Analyzer
- **Category:** Web Application Security / Authentication
- **Source File:** `backend/app/scanner/modules/cookie_scanner.py`
- **Class / Function:** `scan_cookies()`
- **What it tests:**
  1. Missing `Secure` flag on HTTPS targets (`CWE-614`, Low to Medium).
  2. Missing `HttpOnly` flag allowing script access (`CWE-1004`, Low to Medium).
  3. Missing `SameSite` attribute or `SameSite=None` (`CWE-1275`, Low).
  - Uses heuristic analysis to escalate severity from Low (CVSS 2.6) to Medium (CVSS 5.0–5.4) for session cookies (`session`, `sid`, `token`, `auth`, `jwt`, `phpsessid`, `jsessionid`, `laravel_session`, etc.).
- **Input:** List of cookie dictionaries captured during crawling/baseline.
- **Trigger:** Phase 9 of scan orchestrator.
- **Requests:** Evaluates cookies captured from earlier requests (0 additional requests).
- **Evidence:** Cookie name, domain, path, missing flag attributes.
- **Remediation:** Configure application server to add `Secure; HttpOnly; SameSite=Lax` or `Strict` to all session cookies.
- **Execution Mode:** Passive inspection (Non-destructive).

#### 10. JWT Token Security Scanner
- **Check Name:** JSON Web Token (JWT) Security Analyzer
- **Category:** Authentication Security
- **Source File:** `backend/app/scanner/modules/jwt_scanner.py`
- **Class / Function:** `scan_jwt_security()`
- **What it tests:**
  1. `none` algorithm acceptance allowing signature stripping (`CWE-327`, Critical, CVSS 9.8).
  2. Expired JWT tokens still accepted/active (`CWE-613`, Medium, CVSS 5.3).
  3. Missing expiration (`exp`) claim causing indefinite token validity (`CWE-613`, Medium, CVSS 5.3).
  4. Missing security claims (`iss`, `aud`, `iat`) (`CWE-345`, Low, CVSS 3.1).
  5. Weak/common HMAC signing secrets via offline dictionary attack against 16 common secrets (`secret`, `password`, `123456`, `admin`, etc.) (`CWE-521`, Critical, CVSS 9.8).
  6. Sensitive data exposure in unencrypted payload (`password`, `secret`, `ssn`, `credit_card`) (`CWE-312`, High, CVSS 7.5).
- **Input:** Cookies, HTTP Authorization/custom headers, auth login endpoints.
- **Trigger:** Phase 9 of scan orchestrator.
- **Requests:** Parses existing tokens; checks 4 common auth endpoints (`/api/auth/token`, `/auth/login`, etc.) if no token was found.
- **Evidence:** Token header, payload keys, detected secret, or decoded claims.
- **Remediation:** Enforce strong asymmetric signing (RS256/ES256), strict claim validation, short expirations, and reject `none` algorithm.
- **Execution Mode:** Passive token decode + offline signature calculation (Non-destructive).

---

### D. Web Application Vulnerability Testing

#### 11. Cross-Site Request Forgery (CSRF) Scanner
- **Check Name:** Cross-Site Request Forgery Assessment
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/csrf_scanner.py`
- **Class / Function:** `CSRFScanner.scan()`, `_scan_form()`
- **What it tests:** Inspects HTML forms utilizing state-changing methods (`POST`, `PUT`, `DELETE`, `PATCH`) for the absence of anti-CSRF tokens (`csrf`, `token`, `_token`, `authenticity_token`, `__requestverificationtoken`, `anti-forgery`).
- **Input:** Discovered HTML forms.
- **Trigger:** Phase 10 of scan orchestrator.
- **Requests:** Evaluates parsed form inputs from crawling phase.
- **Condition for Finding:** State-changing form contains no input matching anti-CSRF token patterns (`CWE-352`, Medium, CVSS 5.4).
- **Evidence:** Form action URL, HTTP method, and absence of token fields.
- **Remediation:** Implement cryptographically secure anti-CSRF tokens for all state-changing actions.
- **Execution Mode:** Form structure analysis (Non-destructive).

#### 12. Cross-Site Scripting (XSS) Scanner
- **Check Name:** Reflected Cross-Site Scripting Injection
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/xss_scanner.py`
- **Class / Function:** `XSSScanner.scan()`, `_scan_form()`, `_scan_url_param()`, `_analyze_reflection_context()`
- **What it tests:** Injects XSS payloads into discovered form inputs and URL query parameters to evaluate reflection behavior.
- **Payloads:** `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`, `"><script>alert(1)</script>`, etc.
- **Detection Logic:**
  - Performs context-aware reflection analysis: checks if payload is reflected in HTML body, attribute, script tag, or comment.
  - Verifies whether reflection is HTML-entity encoded (`html.escape` check). Safely encoded reflections are **rejected** as false positives.
  - Unencoded reflections in executable contexts are classified as `potential` requiring browser confirmation (`CWE-79`, Medium, CVSS 6.1).
- **Evidence:** Exact reflected snippet with surrounding 50 characters, injection parameter, and reflection context.
- **Remediation:** Apply contextual output encoding, strict input validation, and Content Security Policy.
- **Execution Mode:** Active payload injection (Safe alert-box probes, non-destructive).

#### 13. SQL Injection (SQLi) Scanner
- **Check Name:** SQL Injection Detector
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/sqli_scanner.py`
- **Class / Function:** `SQLiScanner.scan()`, `_check_vulnerability()`
- **What it tests:** Injects structured SQL payloads into forms and URL query parameters to test 4 attack vectors:
  1. **Error-Based:** Injects `'`, `admin'--`. Matches response against 18 regex patterns for MySQL, PostgreSQL, MSSQL, Oracle, and SQLite database errors.
  2. **Time-Based Blind:** Injects sleep commands (`SLEEP(5)`, `WAITFOR DELAY '00:00:05'`, `pg_sleep(5)`). Evaluates if response latency is delayed $\ge 4.5\text{ seconds}$.
  3. **Boolean-Based Blind / Auth Bypass:** Injects `' OR '1'='1`, `' OR 1=1--`. Checks for authentication bypass indicators (`welcome`, `dashboard`, `logged in`).
  4. **UNION-Based:** Injects `' UNION SELECT NULL--` and checks for successful execution.
- **Condition for Finding:** Database error match, verified time delay $\ge 4.5\text{s}$, or auth bypass indicator (`CWE-89`, Critical, CVSS 9.8).
- **Evidence:** Matched database error snippet, measured response latency delay, or bypassed state.
- **Remediation:** Enforce parameterized queries and prepared statements across all database layers.
- **Execution Mode:** Active payload injection (Non-destructive queries / sleep probes).

#### 14. Server-Side Request Forgery (SSRF) Scanner
- **Check Name:** Differential Server-Side Request Forgery Detector
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/ssrf_scanner.py`
- **Class / Function:** `SSRFScanner.scan()`, `_evaluate_ssrf()`
- **What it tests:** Identifies URL-accepting parameters (`url`, `link`, `redirect`, `fetch`, `download`, `webhook`, `callback`, etc.) on forms and query strings.
- **Methodology (Baseline Differential):**
  1. Requests baseline response using benign external target (`https://example.com/baseline_check`).
  2. Injects internal probes:
     - AWS EC2 Metadata: `http://169.254.169.254/latest/meta-data/`
     - GCP Compute Metadata: `http://metadata.google.internal/computeMetadata/v1/`
     - Unix File Protocol: `file:///etc/passwd`
     - Windows File Protocol: `file:///c:/windows/win.ini`
     - Localhost Loopback: `http://127.0.0.1:80/`
  3. Evaluates if test response returned metadata/file signatures that were absent in baseline (`ami-id`, `instance-id`, `root:.*:0:0:`, `[extensions]`, `redis_version`).
- **Condition for Finding:** Differential signature indicator match or backend connection error revealing attempted internal access (`CWE-918`, High, CVSS 8.8).
- **Evidence:** Matched metadata signature, HTTP status, and response snippet.
- **Remediation:** Enforce outbound URL allowlists, restrict protocols (block `file://`), and block access to internal IP ranges (169.254.0.0/16, RFC 1918).
- **Execution Mode:** Active probe with read-only metadata endpoints (Non-destructive).

#### 15. Local File Inclusion (LFI) Scanner
- **Check Name:** Local File Inclusion Detector
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/lfi_scanner.py`
- **Class / Function:** `LFIScanner.scan()`, `_scan_form()`, `_scan_url_param()`
- **What it tests:** Targets file/include parameters (`file`, `path`, `page`, `include`, `dir`, `template`) with paths to sensitive system files.
- **Payloads:** Direct Linux paths (`/etc/passwd`), traversal variants (`../../../../etc/passwd`), Windows paths (`C:\windows\win.ini`), URL-encoded variants (`%2e%2e%2f`), null-byte injection (`/etc/passwd%00`).
- **Condition for Finding:** Response contains evidence strings (`root:`, `bin/bash`, `[extensions]`) (`CWE-22`/`CWE-98`, High, CVSS 8.1).
- **Evidence:** Matched file signatures in HTTP response body.
- **Remediation:** Avoid passing user input to file system APIs; validate paths against a strict server-side whitelist.
- **Execution Mode:** Active read-only file inclusion testing (Non-destructive).

#### 16. XML External Entity (XXE) Scanner
- **Check Name:** XML External Entity Injection Detector
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/xxe_scanner.py`
- **Class / Function:** `XXEScanner.scan()`, `_accepts_xml()`, `_scan_direct()`
- **What it tests:**
  1. Checks if the endpoint accepts XML payloads (`Content-Type: application/xml`).
  2. Sends DOCTYPE definitions declaring external entities pointing to `file:///etc/passwd`, `file:///c:/windows/win.ini`, and metadata IP.
- **Condition for Finding:** Entity reference is expanded in response, disclosing file contents (`root:`, `[extensions]`) (`CWE-611`, High, CVSS 8.6).
- **Evidence:** Extracted file content snippet from XML response.
- **Remediation:** Disable external entity resolution (DTD processing) in XML parsers (`disallow-doctype-decl`).
- **Execution Mode:** Active payload injection (Non-destructive read probes).

#### 17. Remote Code Execution (RCE) Scanner
- **Check Name:** OS Command & Code Execution Detector
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/rce_scanner.py`
- **Class / Function:** `RCEScanner.scan()`, `_test_command_injection()`, `_test_code_execution()`
- **What it tests:**
  1. **Command Injection:** Injects Unix shell delimiters (`;sleep 5`, `| id`, `$(id)`, `;uname -a`) and Windows commands (`& timeout 5`, `& whoami`).
  2. **Code Execution:** Injects language expressions (`phpinfo()`, `${7*7}`, `{{7*7}}`, `system('sleep 5')`).
- **Condition for Finding:** Response exhibits execution signatures (`uid=\d+.*gid=\d+`, `Linux.*\d+`, `phpinfo()`, arithmetic `49`) or verified sleep latency delay $\ge 4.5\text{s}$ (`CWE-78`/`CWE-94`, Critical, CVSS 9.8).
- **Evidence:** Matched execution output or measured sleep duration.
- **Remediation:** Avoid invoking system shells (`exec`, `system`, `popen`) with user-supplied arguments; use safe parameter arrays.
- **Execution Mode:** Active payload injection (Non-destructive sleep/id probes).

#### 18. Insecure Direct Object Reference (IDOR) Scanner
- **Check Name:** Object Identifier Access Control Scanner
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/idor_scanner.py`
- **Class / Function:** `IDORScanner.scan()`, `_analyze_idor_response()`
- **What it tests:** Detects object identifiers (`id`, `user_id`, `account_id`, `order_id`, `file_id`, `doc_id`, etc.) in URL query parameters and forms.
- **Methodology:** Fetches baseline response, mutates ID using test transformations: increment (`+1`), decrement (`-1`), zero (`0`), negative (`-1`), high value (`99999`), and GUID last-character flipping.
- **Condition for Finding:** Mutated request returns HTTP 200 with changed body that leaks sensitive data patterns (emails, phone numbers, SSNs, credit cards, API keys, tokens) (`CWE-639`, High, CVSS 8.6).
- **Evidence:** Leaked sensitive data regex matches, mutated parameter, and status comparison.
- **Remediation:** Enforce server-side record ownership and object-level authorization checks before returning data.
- **Execution Mode:** Active identifier manipulation (Non-destructive read requests).

#### 19. Open URL Redirection Scanner
- **Check Name:** Unvalidated Redirect & Forward Detector
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/open_redirect_scanner.py`
- **Class / Function:** `OpenRedirectScanner.scan()`, `_check_redirect()`
- **What it tests:** Injects external URLs (`https://evil.com`, `//evil.com`, `javascript:alert(1)`) into redirection parameters (`url`, `redirect`, `next`, `return_url`, `goto`, `destination`).
- **Condition for Finding:** Server responds with HTTP 3xx redirect containing `Location: https://evil.com` or body containing meta-refresh/script redirect to attacker domain without following (`CWE-601`, Medium, CVSS 4.3).
- **Evidence:** HTTP status code, `Location` header value, injected parameter.
- **Remediation:** Validate redirection targets against a strict server-side allowlist; use relative paths only.
- **Execution Mode:** Active probe (Non-destructive, does not follow redirects).

#### 20. Path Traversal Scanner
- **Check Name:** Directory Path Traversal Scanner
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/path_traversal_scanner.py`
- **Class / Function:** `PathTraversalScanner.scan()`, `_check_traversal()`
- **What it tests:** Injects directory traversal sequences into file-related parameters (`filename`, `path`, `document`, `folder`, `download`).
- **Payloads:** `../../../etc/passwd`, `..\..\..\windows\win.ini`, URL encoded (`..%2F`), double encoded (`..%252F`), null bytes (`%00`), 16-bit unicode (`..%u002f`).
- **Condition for Finding:** Response contains file signatures (`root:.*:0:0:`, `root:\$`, `127.0.0.1.*localhost`, `[boot loader]`) (`CWE-22`, High, CVSS 8.1).
- **Evidence:** Matched file content regex and traversal payload.
- **Remediation:** Canonicalize paths and enforce strict allowlists of readable files.
- **Execution Mode:** Active path traversal testing (Non-destructive).

#### 21. NoSQL Injection Scanner
- **Check Name:** NoSQL / MongoDB Operator Injection Scanner
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/nosqli_scanner.py`
- **Class / Function:** `NoSQLiScanner.scan()`, `_test_nosql_injection_form()`
- **What it tests:** Targets form inputs (especially authentication fields) and query parameters with NoSQL operator objects (`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`) and JavaScript string injections (`'||'1'=='1`, `'; return true; var foo='`).
- **Condition for Finding:** Compares test response to baseline; triggers if authentication bypass indicators (`login successful`, `welcome`, `dashboard`, `authenticated`) appear (`CWE-943`, High, CVSS 8.8).
- **Evidence:** Bypassed state and payload representation.
- **Remediation:** Use typed schema models (e.g., Mongoose with strict types) and avoid passing raw query objects.
- **Execution Mode:** Active payload injection (Non-destructive).

#### 22. LDAP Injection Scanner
- **Check Name:** LDAP Query Filter Injection Scanner
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/ldapi_scanner.py`
- **Class / Function:** `LDAPIScanner.scan()`, `_test_ldap_injection_form()`
- **What it tests:** Targets search, username, and query fields with LDAP filter metacharacters (`*`, `*)(&`, `*))(|(objectClass=*`, `admin*)((|userPassword=*`).
- **Condition for Finding:** Response exhibits LDAP error messages (`LDAPException`, `javax.naming`, `invalid filter`, `com.sun.jndi.ldap`) or auth bypass (`welcome`, `authenticated`) (`CWE-90`, High, CVSS 8.8).
- **Evidence:** Matched LDAP error pattern or authentication bypass snippet.
- **Remediation:** Use parameterized LDAP queries and escape metacharacters (`*`, `(`, `)`, `\`, `NUL`).
- **Execution Mode:** Active payload injection (Non-destructive).

#### 23. Server-Side Template Injection (SSTI) Scanner
- **Check Name:** Template Expression Injection Scanner
- **Category:** Web Application Security Testing
- **Source File:** `hacktheweb-main/hacktheweb/scanners/ssti_scanner.py`
- **Class / Function:** `SSTIScanner.scan()`, `_test_ssti_form()`
- **What it tests:** Evaluates template injection across 7 engines:
  - **Jinja2:** `{{7*7}}`, `{{7*'7'}}`
  - **FreeMarker:** `${7*7}`, `#{7*7}`
  - **Velocity:** `#set($x=7*7)$x`
  - **Smarty:** `{7*7}`, `{$smarty.version}`
  - **Twig:** `{{7*7}}`, `{{_self}}`
  - **ERB:** `<%= 7*7 %>`
  - **Tornado:** `{{7*7}}`
- **Condition for Finding:** Evaluated arithmetic result (`49` or `7777777`) appears in response where raw string was submitted (`CWE-1336`, Critical, CVSS 9.1).
- **Evidence:** Evaluated arithmetic expression, identified engine name, and response snippet.
- **Remediation:** Never pass untrusted user input directly into template renderers; pass data as template context variables.
- **Execution Mode:** Active payload injection (Safe arithmetic evaluation, non-destructive).

---

### E. API & Service Security

#### 24. API Security & Method Enumeration Scanner
- **Check Name:** REST API Method & Excessive Exposure Analyzer
- **Category:** API Security Testing
- **Source File:** `backend/app/scanner/modules/api_scanner.py`
- **Class / Function:** `scan_api_endpoints()`, `_test_method_enumeration()`, `_test_data_exposure()`, `_test_api_cors()`
- **What it tests:** Tested on up to 30 discovered API routes (`/api/`, `/rest/`, `/v1/`):
  1. **HTTP Method Enumeration:** Tests `OPTIONS`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `TRACE`. Flags HTTP TRACE returning 2xx (`CWE-693`, Medium, CVSS 5.3) and state-changing methods returning 2xx (`CWE-749`, Low, CVSS 3.1).
  2. **Excessive Data Exposure:** Scans JSON/XML responses for PII patterns (`email`, `ssn`, `credit_card`, `phone`, `api_key`) (`CWE-200`, Medium, CVSS 6.5) and unpaginated responses > 100 items & > 50KB (`CWE-770`, Low, CVSS 3.1).
  3. **API CORS Analysis:** Tests API endpoints specifically for origin reflection and credentials (`CWE-942`, High/Medium/Low).
- **Input:** Discovered API endpoint list.
- **Trigger:** Phase 11 of scan orchestrator.
- **Requests:** HTTP requests across alternate methods.
- **Evidence:** Accepted methods list, matched PII count, or CORS header combinations.
- **Remediation:** Restrict HTTP methods, enforce strict JSON response filtering, and apply pagination.
- **Execution Mode:** Active method testing & body pattern matching (Non-destructive).

#### 25. GraphQL Security Scanner
- **Check Name:** GraphQL Schema & Complexity Security Analyzer
- **Category:** API Security Testing
- **Source File:** `backend/app/scanner/modules/graphql_scanner.py`
- **Class / Function:** `scan_graphql_endpoints()`, `_test_introspection()`, `_test_query_depth()`, `_test_batch_queries()`, `_test_error_disclosure()`, `_test_field_suggestions()`
- **What it tests:** Tested on discovered GraphQL endpoints:
  1. **Introspection Query:** Sends `__schema` query; flags if full type schema is disclosed (`CWE-200`, Medium, CVSS 5.3).
  2. **Query Depth Limiting:** Sends query nested 8 levels deep; flags if processed without error (`CWE-770`, Medium, CVSS 5.3) or causes timeout (`CWE-400`, High, CVSS 7.5).
  3. **Batch Query Abuse:** Sends 10 queries in single array; flags if processed without limits (`CWE-770`, Low, CVSS 3.1).
  4. **Error Information Disclosure:** Sends malformed queries; checks for stack traces, internal paths (`/var/`, `/home/`), and ORM names (`CWE-209`, Low, CVSS 3.1).
  5. **Field Suggestions:** Checks if typo queries return schema suggestions ("Did you mean ...") (`CWE-200`, Low, CVSS 2.5).
- **Input:** Discovered GraphQL endpoint URLs.
- **Trigger:** Phase 11 of scan orchestrator.
- **Requests:** HTTP POST requests with JSON GraphQL queries.
- **Evidence:** Disclosed type count, batch execution count, or error disclosure string.
- **Remediation:** Disable introspection and field suggestions in production; implement query depth and batch limits.
- **Execution Mode:** Active GraphQL queries (Non-destructive).

---

## 6. QUALITY GATES & POST-PROCESSING PIPELINE

#### 26. Adaptive Threat Chaining
- **Module:** `backend/app/scanner/adaptive_engine.py` (`AdaptiveEngine`)
- **Execution:** Triggered in Full Scan mode (Phase 12). Evaluates initial findings against 12 vulnerability relationship chains (e.g., SQLi → RCE/LFI, SSRF → RCE/LFI, CORS → CSRF/IDOR, XSS → CSRF).
- **Behavior:** Recommends follow-up scanner modules for attack vector chaining.

#### 27. Active Evidence Verification
- **Module:** `backend/app/scanner/evidence_collector.py` (`EvidenceCollector`)
- **Execution:** Triggered in Full Scan mode (Phase 13). Replays the original HTTP request and payload for up to 15 High and Critical findings.
- **Behavior:** Confirms reproducibility before marking findings as `confirmed`. Findings that fail to reproduce have their confidence reduced to `Low` and status set to `not_reproduced`.

#### 28. Finding Validation & Deduplication Pipeline
- **Module:** `backend/app/scanner/finding_pipeline.py` (`FindingPipeline`)
- **Execution:** Triggered in Phase 13.5 on all raw findings.
- **Behavior:**
  1. Validates minimum evidence requirements per vulnerability type (rejects malformed detections).
  2. Generates a SHA256 root-cause correlation key (`target|finding_type|cwe|param`).
  3. Deduplicates multiple instances of the same vulnerability across different endpoints into a single master finding, embedding the full list in `metadata_json['grouped_endpoints']`.

#### 29. Risk Scoring & Classification
- **Module:** `backend/app/core/owasp.py`
- **Execution:** Triggered during finding normalization.
- **Behavior:** Dynamically calculates CVSS v3.1 base score, vector, and severity. Re-derives severity directly from the numeric CVSS score so scores and severity ratings never conflict:
  - Critical: $9.0 - 10.0$
  - High: $7.0 - 8.9$
  - Medium: $4.0 - 6.9$
  - Low: $0.1 - 3.9$
  - Info: $0.0$

---

## 7. RESOLUTION OF IDENTIFIED EXECUTION ISSUES

The execution issues identified during the initial code audit have been resolved with minimal, safe fixes in `orchestrator.py` and `evidence_collector.py`:

| Module | File Location | Resolution Summary | Status Post-Fix |
|---|---|---|---|
| **Port Scanner** | `backend/app/scanner/modules/port_scanner.py` | Orchestrator call corrected from `scan_ports()` to imported `run_port_scan(host, emit=port_emit)`. Verified open ports are returned and persisted. | **IMPLEMENTED + EXECUTED** |
| **Service Detector** | `backend/app/scanner/modules/service_detector.py` | Synchronous invocation corrected to `detect_services(open_ports, http_headers=http_headers)`. Successfully fingerprints services when ports are identified. | **IMPLEMENTED + EXECUTED** |
| **OS Detector** | `backend/app/scanner/modules/os_detector.py` | Orchestrator call corrected from `detect_operating_system()` to `detect_os(host, open_ports=open_ports, http_headers=http_headers)`. Failures and low-confidence results handled defensively. | **IMPLEMENTED + EXECUTED** |
| **CVE Lookup** | `backend/app/scanner/modules/cve_lookup.py` | Integrated `lookup_cves(services)` after service fingerprinting. Findings normalized as `service_vulnerability`, processed by quality pipeline and persisted. | **IMPLEMENTED + EXECUTED** |
| **TLS Analyzer** | `backend/app/scanner/modules/tls_analyzer.py` | Legacy file; superseded by active `tls_scanner.py`. | **SUPERSEDED / UNUSED** |

---

## 8. MISSING / NOT IMPLEMENTED CHECKS

The following security checks are **not implemented** in the Orion codebase:
1. **Subdomain Takeover:** No CNAME resolution checking against orphaned cloud services (AWS S3, GitHub Pages, etc.).
2. **WebSocket Fuzzing:** Intercepts WebSocket URLs via Playwright, but performs no active WebSocket frame fuzzing.
3. **HTTP Request Smuggling:** No CL.TE or TE.CL desynchronization probes.
4. **SAML / OAuth Flow Exploitation:** No SAML XML signature wrapping or OAuth redirect validation checks.
5. **Business Logic Flaws:** Automated AST only; no multi-step state machine testing.

---

## 9. FINAL VERIFIED METHODOLOGY

Based exclusively on verified code execution, the defensible Orion methodology consists of the following sections:

### RECONNAISSANCE & ASSET DISCOVERY
• **DNS Record Enumeration:** Resolution of authoritative A, AAAA, MX, NS, TXT, and SOA records.  
• **Subdomain Dictionary Discovery:** DNS resolution of 45 common organizational subdomain prefixes.  
• **WHOIS Registration Intelligence:** Querying domain registrars for creation, expiration, and ownership data.  
• **Target Stack Fingerprinting:** Passive inference of web servers, frameworks, CMS platforms, and UI libraries.

### ATTACK SURFACE MAPPING
• **Web Application Crawling:** Extraction of URL routes, HTML forms, input parameters, and script tags within scope.  
• **Site Structure Discovery:** Automated parsing of `robots.txt` and `sitemap.xml` navigation hierarchies.  
• **Single-Page Application Discovery:** Headless Chromium DOM execution and dynamic XHR/Fetch route interception.

### SECURITY CONFIGURATION & POSTURE
• **Transport Layer Security (TLS/SSL):** Verification of HTTPS enforcement, protocol versions, ciphers, and certificate validity.  
• **HTTP Security Headers:** Verification of Content-Security-Policy, HSTS, X-Content-Type-Options, clickjacking, and Referrer-Policy.  
• **CORS Architecture Analysis:** Testing for arbitrary origin reflection, credentials leakage, null origin, and wildcard scopes.  
• **Cookie & Token Security:** Verification of Secure, HttpOnly, and SameSite flags on session tokens.  
• **JSON Web Token (JWT) Security:** Validation of signature algorithms, claim expiration, and weak secret dictionaries.

### WEB APPLICATION VULNERABILITY TESTING
• **Cross-Site Scripting (XSS):** Active payload injection into forms and URL query parameters with reflection context analysis.  
• **SQL Injection (SQLi):** Testing of error-based, time-based blind, boolean-based, and UNION-based database injection flaws.  
• **Server-Side Request Forgery (SSRF):** Differential baseline comparison against cloud metadata and local loopback protocols.  
• **File Inclusion & Directory Traversal:** Probing of file/path parameters for sensitive system files across Linux and Windows.  
• **XML External Entity (XXE):** Testing of XML endpoints for external DTD entity expansion and file retrieval.  
• **Command & Code Injection (RCE):** Probing input fields with safe shell delimiters and arithmetic evaluation probes.  
• **Access Control & IDOR:** Parameter mutation of resource identifiers with sensitive pattern leakage detection.  
• **Open URL Redirection:** Probing redirection parameters for unvalidated external location redirects.  
• **NoSQL & LDAP Injection:** Injection of MongoDB operator expressions and LDAP filter metacharacters.  
• **Template Injection (SSTI):** Probing template syntax across Jinja2, FreeMarker, Velocity, Smarty, Twig, and ERB.

### API SECURITY & QUALITY GATES
• **REST API Method Enumeration:** Verification of HTTP TRACE and state-changing method restrictions.  
• **Excessive Data Exposure:** Automated pattern detection of PII and unpaginated bulk responses.  
• **GraphQL Security Testing:** Probing of introspection queries, query depth thresholds, batch limits, and error disclosure.  
• **Active Evidence Verification:** Automated replay verification of High and Critical findings.  
• **Correlation & Quality Pipeline:** Root-cause SHA256 correlation, deduplication, and dynamic CVSS v3.1 calculation.
