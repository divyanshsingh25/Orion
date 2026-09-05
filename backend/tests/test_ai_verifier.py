from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Dict, List

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.security_sanitizer import SecuritySanitizer
from app.services.deterministic_verifier import DeterministicVerifier
from app.services.ai_verifier import AIVerifier


# --- Benchmark Dataset of Standard Scanner Findings ---
BENCHMARK_FINDINGS = [
    # 1. True Positive: Raw unencoded XSS in HTML
    {
        "id": "fp-test-01",
        "title": "Reflected Cross-Site Scripting (XSS)",
        "finding_type": "xss",
        "severity": "High",
        "confidence": "Certain",
        "affected_url": "https://example.com/search?q=<script>alert(1)</script>",
        "affected_parameter": "q",
        "evidence": "Payload reflected unencoded in HTML body: <div>Search: <script>alert(1)</script></div>",
        "http_request": "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<div>Search: <script>alert(1)</script></div>",
        "expected_verdict": "CONFIRMED",
    },
    # 2. False Positive: XSS payload safely entity-encoded by server
    {
        "id": "fp-test-02",
        "title": "Reflected Cross-Site Scripting (XSS)",
        "finding_type": "xss",
        "severity": "High",
        "confidence": "Medium",
        "affected_url": "https://example.com/profile?name=<script>alert(1)</script>",
        "affected_parameter": "name",
        "evidence": "Observed reflection in response: &lt;script&gt;alert(1)&lt;/script&gt;",
        "http_request": "GET /profile?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<span>Hello, &lt;script&gt;alert(1)&lt;/script&gt;</span>",
        "expected_verdict": "FALSE_POSITIVE",
    },
    # 3. False Positive: Reflection inside application/json API endpoint
    {
        "id": "fp-test-03",
        "title": "Cross-Site Scripting in JSON API",
        "finding_type": "xss",
        "severity": "Medium",
        "confidence": "Medium",
        "affected_url": "https://example.com/api/v1/user?q=<script>alert(1)</script>",
        "affected_parameter": "q",
        "evidence": "JSON response reflected string: {\"status\": \"ok\", \"query\": \"<script>alert(1)</script>\"}",
        "http_request": "GET /api/v1/user?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"status\": \"ok\", \"query\": \"<script>alert(1)</script>\"}",
        "expected_verdict": "FALSE_POSITIVE",
    },
    # 4. Inconclusive / Potential: Reflection alone without full DOM context
    {
        "id": "fp-test-04",
        "title": "Possible Reflected Parameter",
        "finding_type": "xss",
        "severity": "Low",
        "confidence": "Low",
        "affected_url": "https://example.com/track?ref=xyz123",
        "affected_parameter": "ref",
        "evidence": "Parameter xyz123 was echoed back in page footer.",
        "http_request": "GET /track?ref=xyz123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!-- ref: xyz123 -->",
        "expected_verdict": "POTENTIAL",
    },
    # 5. Rule Guard: HTTP OPTIONS Allow header alone is NOT False Positive and NOT Confirmed (must be POTENTIAL)
    {
        "id": "fp-test-05",
        "title": "Potentially Insecure HTTP Methods Allowed (OPTIONS)",
        "finding_type": "http_method",
        "severity": "Low",
        "confidence": "Tentative",
        "affected_url": "https://example.com/api/upload",
        "affected_parameter": None,
        "evidence": "Server header Allow: GET, POST, OPTIONS, PUT, DELETE",
        "http_request": "OPTIONS /api/upload HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 200 OK\r\nAllow: GET, POST, OPTIONS, PUT, DELETE\r\nContent-Length: 0\r\n\r\n",
        "expected_verdict": "POTENTIAL",
    },
    # 6. False Positive: Active PUT method rejected with 403 Forbidden
    {
        "id": "fp-test-06",
        "title": "Arbitrary File Upload via Insecure HTTP PUT",
        "finding_type": "http_method",
        "severity": "High",
        "confidence": "Medium",
        "affected_url": "https://example.com/uploads/test.txt",
        "affected_parameter": None,
        "evidence": "Attempted PUT /uploads/test.txt received response 403 Forbidden",
        "http_request": "PUT /uploads/test.txt HTTP/1.1\r\nHost: example.com\r\n\r\nTest content",
        "http_response": "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\nAccess Denied",
        "expected_verdict": "FALSE_POSITIVE",
    },
    # 7. True Positive: Active PUT method created file with 201 Created
    {
        "id": "fp-test-07",
        "title": "Arbitrary File Upload via Insecure HTTP PUT",
        "finding_type": "http_method",
        "severity": "Critical",
        "confidence": "Certain",
        "affected_url": "https://example.com/uploads/test.txt",
        "affected_parameter": None,
        "evidence": "Server created file at /uploads/test.txt with status 201 Created",
        "http_request": "PUT /uploads/test.txt HTTP/1.1\r\nHost: example.com\r\n\r\nPoC Verification",
        "http_response": "HTTP/1.1 201 Created\r\nLocation: /uploads/test.txt\r\n\r\nFile Created Successfully",
        "expected_verdict": "CONFIRMED",
    },
    # 8. Rule Guard: Passive banner match alone must be POTENTIAL (never Confirmed)
    {
        "id": "fp-test-08",
        "title": "CVE-2021-41773 Apache Path Traversal via Version Banner",
        "finding_type": "cve",
        "severity": "Critical",
        "confidence": "Medium",
        "affected_url": "https://example.com/",
        "affected_parameter": None,
        "evidence": "Server banner detected: Apache/2.4.49 (Unix)",
        "http_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n<html>Apache Welcome</html>",
        "expected_verdict": "POTENTIAL",
    },
    # 9. True Positive: Active exploit proof for CVE path traversal
    {
        "id": "fp-test-09",
        "title": "CVE-2021-41773 Apache Path Traversal Exploit",
        "finding_type": "cve",
        "severity": "Critical",
        "confidence": "Certain",
        "affected_url": "https://example.com/cgi-bin/.%2e/.%2e/bin/sh",
        "affected_parameter": None,
        "evidence": "Root password file extracted: root:x:0:0:root:/root:/bin/bash",
        "http_request": "POST /cgi-bin/.%2e/.%2e/bin/sh HTTP/1.1\r\nHost: example.com\r\n\r\necho; cat /etc/passwd",
        "http_response": "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "expected_verdict": "CONFIRMED",
    },
    # 10. True Positive: SQL Injection with syntax error reflected
    {
        "id": "fp-test-10",
        "title": "SQL Injection (Error-Based)",
        "finding_type": "sqli",
        "severity": "Critical",
        "confidence": "Certain",
        "affected_url": "https://example.com/items?id=1'",
        "affected_parameter": "id",
        "evidence": "Database error reflected: syntax error in string '1'' in PostgreSQL query.",
        "http_request": "GET /items?id=1%27 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "http_response": "HTTP/1.1 500 Internal Server Error\r\n\r\nPostgreSQL ERROR: syntax error in string '1'' at character 42",
        "expected_verdict": "CONFIRMED",
    },
]


# ==============================================================================
# UNIT TESTS
# ==============================================================================

def test_security_sanitizer_redaction():
    """Verify that credentials, auth headers, and session cookies are redacted."""
    raw_text = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.xyz12345\n"
        "Cookie: PHPSESSID=d9a8f7b6c5e4d3a2b10000; sessionid=admin_session_secret_999\n"
        "Config: api_key=sk-proj-999988887777666655554444\n"
        "Payload: {'password': 'SuperSecretPassword123'}"
    )
    sanitized = SecuritySanitizer.sanitize_text(raw_text)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "d9a8f7b6c5e4d3a2b10000" not in sanitized
    assert "sk-proj-999988887777666655554444" not in sanitized
    assert "SuperSecretPassword123" not in sanitized
    assert "[REDACTED_BEARER_TOKEN]" in sanitized
    assert "[REDACTED_SESSION_COOKIE]" in sanitized
    assert "[REDACTED_SECRET]" in sanitized or "[REDACTED_API_KEY]" in sanitized


def test_xss_rules():
    """Verify XSS reflection ground-truth rules."""
    # Entity-encoded -> FALSE_POSITIVE
    encoded_xss = {
        "finding_type": "xss",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n&lt;script&gt;alert(1)&lt;/script&gt;",
    }
    assert DeterministicVerifier.verify(encoded_xss)["verdict"] == "FALSE_POSITIVE"

    # JSON content-type -> FALSE_POSITIVE
    json_xss = {
        "finding_type": "xss",
        "http_response": 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"q": "<script>alert(1)</script>"}',
    }
    assert DeterministicVerifier.verify(json_xss)["verdict"] == "FALSE_POSITIVE"

    # Unencoded script in HTML -> CONFIRMED
    raw_xss = {
        "finding_type": "xss",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<div><script>alert(1)</script></div>",
    }
    assert DeterministicVerifier.verify(raw_xss)["verdict"] == "CONFIRMED"


def test_http_methods_allow_header_rule():
    """Allow header alone is NOT False Positive and NOT Confirmed; must be POTENTIAL."""
    allow_header_finding = {
        "finding_type": "http_method",
        "http_req": "OPTIONS / HTTP/1.1",
        "http_response": "HTTP/1.1 200 OK\r\nAllow: GET, POST, OPTIONS, PUT, DELETE\r\n\r\n",
    }
    result = DeterministicVerifier.verify(allow_header_finding)
    assert result["verdict"] == "POTENTIAL"
    assert "allow_header_insufficient_evidence_guard" in result["checks_applied"]


def test_cve_banner_passive_matching_rule():
    """Passive banner version string alone must NOT confirm a CVE (must be POTENTIAL)."""
    banner_cve = {
        "finding_type": "cve",
        "title": "CVE-2021-41773 Apache RCE",
        "http_response": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n",
    }
    result = DeterministicVerifier.verify(banner_cve)
    assert result["verdict"] == "POTENTIAL"
    assert "passive_banner_match_guard" in result["checks_applied"]


async def test_ai_verifier_resilience_and_separation():
    """Verify that original scanner results are preserved separately and verifier does not crash."""
    verifier = AIVerifier()
    raw_sample = {
        "finding_type": "xss",
        "title": "Test XSS",
        "severity": "High",
        "confidence": "Tentative",
        "evidence": "reflected &lt;script&gt;",
        "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n&lt;script&gt;alert(1)&lt;/script&gt;",
    }

    result = await verifier.verify_finding(raw_sample)

    # Scanner result preserved intact
    assert result["scanner_result"]["confidence"] == "Tentative"
    assert result["scanner_result"]["severity"] == "High"

    # Deterministic and AI verdicts stored separately
    assert "deterministic_verification" in result
    assert "ai_verification" in result
    assert result["final_classification"] == "FALSE_POSITIVE"


async def test_false_positive_reduction_benchmark():
    """Benchmark test dataset of 10 findings to measure false positive detection."""
    verifier = AIVerifier()

    total = len(BENCHMARK_FINDINGS)
    raw_scanner_flagged = total  # Initially, scanner flagged all 10 as potential vulnerabilities
    confirmed_count = 0
    potential_count = 0
    false_positive_count = 0

    for item in BENCHMARK_FINDINGS:
        res = await verifier.verify_finding(item)
        verdict = res["final_classification"]

        assert verdict == item["expected_verdict"], (
            f"Finding '{item['title']}' expected {item['expected_verdict']}, got {verdict}. "
            f"Reasoning: {res['verification_reasoning']}"
        )

        if verdict == "CONFIRMED":
            confirmed_count += 1
        elif verdict == "POTENTIAL":
            potential_count += 1
        elif verdict == "FALSE_POSITIVE":
            false_positive_count += 1

    # Print benchmark summary
    print("\n" + "=" * 60)
    print("AI VERIFICATION FALSE POSITIVE BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Total Scanner Ingested Findings: {total}")
    print(f"  - Confirmed True Positives:     {confirmed_count} ({(confirmed_count/total)*100:.1f}%)")
    print(f"  - Inconclusive / Potential:     {potential_count} ({(potential_count/total)*100:.1f}%)")
    print(f"  - Verified False Positives:     {false_positive_count} ({(false_positive_count/total)*100:.1f}%)")
    print(f"False Positive Noise Filtered Out: {(false_positive_count/total)*100:.1f}%")
    print("=" * 60 + "\n")

    assert false_positive_count == 3  # Exactly the 3 noisy/escaped/rejected findings
    assert confirmed_count == 4       # Exactly the 4 genuine exploit findings
    assert potential_count == 3       # Exactly the 3 banner/allow/inconclusive findings


if __name__ == "__main__":
    print("Running Security Sanitizer tests...")
    test_security_sanitizer_redaction()
    print("PASS: Security Sanitizer tests passed.")

    print("Running XSS Rule tests...")
    test_xss_rules()
    print("PASS: XSS Rule tests passed.")

    print("Running HTTP Method Rule tests...")
    test_http_methods_allow_header_rule()
    print("PASS: HTTP Method Rule tests passed.")

    print("Running CVE Banner Rule tests...")
    test_cve_banner_passive_matching_rule()
    print("PASS: CVE Banner Rule tests passed.")

    print("Running AI Verifier Resilience & Separation tests...")
    asyncio.run(test_ai_verifier_resilience_and_separation())
    print("PASS: Resilience & Separation tests passed.")

    print("Running False Positive Reduction Benchmark...")
    asyncio.run(test_false_positive_reduction_benchmark())
    print("ALL TESTS & BENCHMARKS PASSED SUCCESSFULLY!")
