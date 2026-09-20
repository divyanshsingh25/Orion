"""
CORS (Cross-Origin Resource Sharing) Scanner
Detects genuine CORS misconfigurations based on real response headers and Origin behavior.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse


class CORSScanner:
    """Scanner for CORS misconfiguration vulnerabilities with verified evidence."""
    
    def __init__(self, config, session):
        """Initialize CORS scanner."""
        self.config = config
        self.session = session
        self.vulnerabilities = []
        
        # Test origins
        self.test_origins = [
            'https://evil-attacker-probe.com',
            'null',
        ]
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for CORS misconfigurations on target and discovered endpoints."""
        self.vulnerabilities = []
        tested_urls = set()
        
        # Test main target
        await self._test_cors(target)
        tested_urls.add(target)
        
        # Test API endpoints if discovered
        if recon_data.get('links'):
            api_endpoints = [
                link for link in recon_data['links'] 
                if isinstance(link, str) and any(kw in link.lower() for kw in ('/api/', '/v1/', '/v2/', '/rest/', '/graphql'))
            ]
            for endpoint in api_endpoints[:5]:
                if endpoint not in tested_urls:
                    tested_urls.add(endpoint)
                    await self._test_cors(endpoint)
        
        return self.vulnerabilities
    
    async def _test_cors(self, url: str):
        """Test URL for CORS misconfigurations against actual HTTP responses."""
        found_for_url = set()

        # Test 1: Reflected Origin check
        for origin in self.test_origins:
            headers = {'Origin': origin}
            try:
                async with self.session.get(url, headers=headers, timeout=8) as response:
                    # Check case-insensitively for headers
                    acao = response.headers.get('Access-Control-Allow-Origin', '').strip()
                    acac = response.headers.get('Access-Control-Allow-Credentials', '').strip().lower()
                    status_code = response.status

                    if not acao:
                        continue
                    
                    # Critical: Reflects arbitrary origin with credentials
                    if acao == origin and acac == 'true':
                        key = f"{url}|reflected_credentials|{origin}"
                        if key not in found_for_url:
                            found_for_url.add(key)
                            self.vulnerabilities.append({
                                'type': 'cors',
                                'severity': 'high',
                                'confidence': 'Confirmed',
                                'verification_status': 'confirmed',
                                'url': url,
                                'affected_url': url,
                                'method': 'GET',
                                'title': 'CORS misconfiguration: arbitrary origin reflected with credentials',
                                'description': f'The server reflects untrusted Origin "{origin}" in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true, enabling authenticated cross-origin data theft.',
                                'evidence': (
                                    f"Endpoint: {url}\n"
                                    f"HTTP Method: GET\n"
                                    f"Status: HTTP {status_code}\n"
                                    f"Request Header: Origin: {origin}\n"
                                    f"Response Header: Access-Control-Allow-Origin: {acao}\n"
                                    f"Response Header: Access-Control-Allow-Credentials: {acac}\n"
                                    f"Detection Reason: Arbitrary origin reflected with credentials enabled"
                                ),
                                'remediation': 'Do not dynamically reflect arbitrary Origin headers. Maintain an explicit allowlist of trusted origins and never combine credentials with dynamic reflection.',
                                'cwe': 'CWE-942',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                            })
                    
                    # Medium: Reflects arbitrary origin without credentials
                    elif acao == origin and origin != 'null':
                        key = f"{url}|reflected|{origin}"
                        if key not in found_for_url:
                            found_for_url.add(key)
                            self.vulnerabilities.append({
                                'type': 'cors',
                                'severity': 'medium',
                                'confidence': 'High',
                                'verification_status': 'confirmed',
                                'url': url,
                                'affected_url': url,
                                'method': 'GET',
                                'title': 'CORS misconfiguration: arbitrary origin reflected',
                                'description': f'The server dynamically reflects arbitrary Origin "{origin}" in Access-Control-Allow-Origin.',
                                'evidence': (
                                    f"Endpoint: {url}\n"
                                    f"HTTP Method: GET\n"
                                    f"Status: HTTP {status_code}\n"
                                    f"Request Header: Origin: {origin}\n"
                                    f"Response Header: Access-Control-Allow-Origin: {acao}\n"
                                    f"Detection Reason: Arbitrary Origin reflected in response header"
                                ),
                                'remediation': 'Validate Origin against a server-side allowlist instead of blindly reflecting untrusted request headers.',
                                'cwe': 'CWE-942',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                            })
                    
                    # Null origin allowed with credentials
                    elif origin == 'null' and acao == 'null' and acac == 'true':
                        key = f"{url}|null_credentials"
                        if key not in found_for_url:
                            found_for_url.add(key)
                            self.vulnerabilities.append({
                                'type': 'cors',
                                'severity': 'high',
                                'confidence': 'Confirmed',
                                'verification_status': 'confirmed',
                                'url': url,
                                'affected_url': url,
                                'method': 'GET',
                                'title': 'CORS misconfiguration: null origin allowed with credentials',
                                'description': 'The server permits the "null" Origin with credentials, allowing exploitation via sandboxed iframes.',
                                'evidence': (
                                    f"Endpoint: {url}\n"
                                    f"HTTP Method: GET\n"
                                    f"Status: HTTP {status_code}\n"
                                    f"Request Header: Origin: null\n"
                                    f"Response Header: Access-Control-Allow-Origin: null\n"
                                    f"Response Header: Access-Control-Allow-Credentials: {acac}\n"
                                    f"Detection Reason: Null origin accepted with credentials enabled"
                                ),
                                'remediation': 'Never allow "null" origin in CORS configuration.',
                                'cwe': 'CWE-942',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                            })
            except Exception:
                pass
        
        # Test 2: Wildcard CORS check (only if target genuinely responds with ACAO: *)
        try:
            async with self.session.get(url, timeout=8) as response:
                acao = response.headers.get('Access-Control-Allow-Origin', '').strip()
                acac = response.headers.get('Access-Control-Allow-Credentials', '').strip().lower()
                status_code = response.status
                
                if acao == '*':
                    if acac == 'true':
                        key = f"{url}|wildcard_credentials"
                        if key not in found_for_url:
                            found_for_url.add(key)
                            self.vulnerabilities.append({
                                'type': 'cors',
                                'severity': 'medium',
                                'confidence': 'Confirmed',
                                'verification_status': 'confirmed',
                                'url': url,
                                'affected_url': url,
                                'method': 'GET',
                                'title': 'CORS wildcard origin with credentials configuration',
                                'description': 'The server sets Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true. While modern browsers reject this combination, it indicates server-side misconfiguration.',
                                'evidence': (
                                    f"Endpoint: {url}\n"
                                    f"HTTP Method: GET\n"
                                    f"Status: HTTP {status_code}\n"
                                    f"Response Header: Access-Control-Allow-Origin: *\n"
                                    f"Response Header: Access-Control-Allow-Credentials: {acac}\n"
                                    f"Detection Reason: Target returned wildcard origin header with credentials flag"
                                ),
                                'remediation': 'Never combine wildcard (*) origin with credentials.',
                                'cwe': 'CWE-942',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                            })
                    else:
                        key = f"{url}|wildcard"
                        if key not in found_for_url:
                            found_for_url.add(key)
                            self.vulnerabilities.append({
                                'type': 'cors',
                                'severity': 'low',
                                'confidence': 'Confirmed',
                                'verification_status': 'confirmed',
                                'cvss': 3.0,
                                'url': url,
                                'affected_url': url,
                                'method': 'GET',
                                'title': 'Permissive CORS wildcard origin (*)',
                                'description': 'The resource returns Access-Control-Allow-Origin: *, allowing any public origin to read its content. If this endpoint hosts non-public data, restrict origins.',
                                'evidence': (
                                    f"Endpoint: {url}\n"
                                    f"HTTP Method: GET\n"
                                    f"Status: HTTP {status_code}\n"
                                    f"Response Header: Access-Control-Allow-Origin: *\n"
                                    f"Detection Reason: Target returned Access-Control-Allow-Origin: * in response"
                                ),
                                'remediation': 'If this endpoint exposes sensitive data, specify explicit allowed origins instead of wildcard (*). For public static content, wildcard is acceptable.',
                                'cwe': 'CWE-942',
                                'owasp': 'A05:2021 - Security Misconfiguration',
                            })
        except Exception:
            pass
        
        # Test 3: Pre-flight request misconfigurations
        await self._test_preflight(url, found_for_url)
    
    async def _test_preflight(self, url: str, found_for_url: set):
        """Test CORS pre-flight (OPTIONS) request."""
        headers = {
            'Origin': 'https://evil-attacker-probe.com',
            'Access-Control-Request-Method': 'PUT',
            'Access-Control-Request-Headers': 'X-Custom-Header',
        }
        try:
            async with self.session.options(url, headers=headers, timeout=8) as response:
                acao = response.headers.get('Access-Control-Allow-Origin', '').strip()
                acam = response.headers.get('Access-Control-Allow-Methods', '').strip()
                status_code = response.status
                
                if not acao:
                    return
                
                dangerous_methods = ['PUT', 'DELETE', 'PATCH']
                allowed_methods = [m.strip().upper() for m in acam.split(',') if m.strip()]
                dangerous_allowed = [m for m in dangerous_methods if m in allowed_methods]
                
                if dangerous_allowed and acao == 'https://evil-attacker-probe.com':
                    key = f"{url}|preflight_methods"
                    if key not in found_for_url:
                        found_for_url.add(key)
                        self.vulnerabilities.append({
                            'type': 'cors',
                            'severity': 'medium',
                            'confidence': 'Confirmed',
                            'verification_status': 'confirmed',
                            'url': url,
                            'affected_url': url,
                            'method': 'OPTIONS',
                            'title': 'CORS preflight allows dangerous HTTP methods from arbitrary origin',
                            'description': f'Preflight response allows state-changing methods ({", ".join(dangerous_allowed)}) for arbitrary origin https://evil-attacker-probe.com.',
                            'evidence': (
                                f"Endpoint: {url}\n"
                                f"HTTP Method: OPTIONS\n"
                                f"Status: HTTP {status_code}\n"
                                f"Request Header: Origin: https://evil-attacker-probe.com\n"
                                f"Response Header: Access-Control-Allow-Origin: {acao}\n"
                                f"Response Header: Access-Control-Allow-Methods: {acam}\n"
                                f"Detection Reason: Dangerous methods permitted for unverified origin in OPTIONS preflight"
                            ),
                            'remediation': 'Restrict Access-Control-Allow-Methods to read-only methods unless strictly required, and validate origins.',
                            'cwe': 'CWE-942',
                            'owasp': 'A05:2021 - Security Misconfiguration',
                        })
        except Exception:
            pass
