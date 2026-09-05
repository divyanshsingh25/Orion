# Third-Party Notices & Attribution

This document contains licensing and copyright notices for third-party open-source software components incorporated into or distributed with the ORION platform.

The top-level ORION platform is licensed under the MIT License (see `LICENSE`), Copyright (c) 2026 Divyansh Singh.

---

## HackTheWeb

This project incorporates code from HackTheWeb.

* **Project**: HackTheWeb
* **Copyright**: Copyright (c) 2025 YashAB Cyber Security (Yashab Alam)
* **Source**: https://github.com/yashab-cyber/hacktheweb
* **Licensed under**: MIT License

---

### Code Separation & Provenance

* **HackTheWeb-Derived Code**:
  ORION does not claim authorship or ownership of the original HackTheWeb code. The retained HackTheWeb components located under `hacktheweb-main/` remain Copyright (c) 2025 YashAB Cyber Security (Yashab Alam) and include:
  * **Core Heuristics & Config**: `hacktheweb/core/ai_engine.py`, `hacktheweb/core/config.py`
  * **Reconnaissance Engine**: `hacktheweb/recon/recon_engine.py`
  * **Target Vulnerability Scanners (`hacktheweb/scanners/`)**:
    * `cors_scanner.py`
    * `csrf_scanner.py`
    * `idor_scanner.py`
    * `ldapi_scanner.py`
    * `lfi_scanner.py`
    * `nosqli_scanner.py`
    * `open_redirect_scanner.py`
    * `path_traversal_scanner.py`
    * `rce_scanner.py`
    * `security_headers_scanner.py`
    * `sqli_scanner.py`
    * `ssrf_scanner.py`
    * `ssti_scanner.py`
    * `xss_scanner.py`
    * `xxe_scanner.py`
  * **Data Loader & Logging Utilities**: `hacktheweb/utils/data_loader.py`, `hacktheweb/utils/logger.py`
  * **Payload Wordlists (`data/`)**: `common_endpoints.txt`, `common_passwords.txt`, `common_usernames.txt`, `file_extensions.txt`, `sensitive_files_linux.txt`, `sensitive_files_windows.txt`, `sqli_payloads.txt`, `technology_fingerprints.txt`, `user_agents.txt`, `xss_payloads.txt`

* **ORION-Original Code**:
  All platform infrastructure, user interfaces, and custom analysis pipelines are original works Copyright (c) 2026 Divyansh Singh, including:
  * **Frontend**: Entire React 18 + Vite + Tailwind CSS + shadcn/ui dashboard, telemetry monitors, interactive canvas charts, and desktop pet companion interface (`frontend/`).
  * **Backend Platform & Services**: FastAPI application structure, async PostgreSQL models and migrations, Celery asynchronous task queues, Redis pub/sub, JWT authentication, and WebSocket live log streaming.
  * **ORION Orchestrator & Multi-Stage Pipelines**: `orchestrator.py`, `adaptive_engine.py`, `safety.py`, `finding_pipeline.py`.
  * **Multi-Engine Verifier**: Deterministic proof verification, AI/LLM verification pipeline (`ai_verifier.py`, `deterministic_verifier.py`, `ai_service.py`).
  * **Executive Reporting**: Native PDF, HTML, and JSON report generator (`reports/generator.py`).
  * **ORION Native Scanner Modules**: `playwright_crawler.py`, `web_crawler.py`, `tls_analyzer.py`, `tls_scanner.py`, `jwt_scanner.py`, `graphql_scanner.py`, `api_scanner.py`, `port_scanner.py`, `service_detector.py`, `dns_enumerator.py`, `whois_lookup.py`, `cve_lookup.py`, `os_detector.py`, `cookie_scanner.py`.

---

### HackTheWeb MIT License Text

```text
MIT License

Copyright (c) 2025 YashAB Cyber Security

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
