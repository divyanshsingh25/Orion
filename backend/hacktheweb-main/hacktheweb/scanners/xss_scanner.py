"""
XSS (Cross-Site Scripting) Scanner
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs
import html
from ..utils.data_loader import data_loader


class XSSScanner:
    """Scanner for XSS vulnerabilities"""
    
    def __init__(self, config, session):
        """Initialize XSS scanner"""
        self.config = config
        self.session = session
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads from data file"""
        # Load payloads from data file
        file_payloads = data_loader.load_xss_payloads()
        
        # Basic fallback payloads if file is empty
        basic_payloads = [
            # Basic payloads
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            
            # Event handlers
            '<div onmouseover=alert(1)>test</div>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            
            # Encoded payloads
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            
            # Special contexts
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '</script><script>alert(1)</script>',
            
            # DOM-based
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            
            # Polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//',
        ]
        
        # Use file payloads if available, otherwise use basic payloads
        return file_payloads if file_payloads else basic_payloads
    
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities concurrently with request timeouts."""
        import asyncio
        vulnerabilities = []
        sem = asyncio.Semaphore(8)  # Concurrency limit to prevent overwhelming target
        
        forms = recon_data.get('forms', [])
        inputs = [inp for inp in recon_data.get('inputs', []) if inp.get('type') == 'url_param']
        
        # Deduplicate URL parameters by (url, parameter_name)
        unique_inputs = []
        seen_keys = set()
        for inp in inputs:
            p_url = inp.get('url') or target
            p_name = inp.get('name')
            if p_name and (p_url, p_name) not in seen_keys:
                seen_keys.add((p_url, p_name))
                unique_inputs.append(inp)

        # Build concurrent task lists
        tasks = []
        for form in forms:
            tasks.append(self._scan_form_sem(target, form, sem))
        
        for param in unique_inputs:
            p_url = param.get('url') or target
            tasks.append(self._scan_url_param_sem(p_url, param, sem))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    vulnerabilities.extend(res)

        return vulnerabilities

    async def _scan_form_sem(self, base_url: str, form: Dict[str, Any], sem: Any) -> List[Dict[str, Any]]:
        async with sem:
            return await self._scan_form(base_url, form)

    async def _scan_url_param_sem(self, url: str, param: Dict[str, Any], sem: Any) -> List[Dict[str, Any]]:
        async with sem:
            return await self._scan_url_param(url, param)

    async def _scan_form(self, base_url: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan form for XSS with context-aware reflection analysis."""
        import aiohttp
        vulnerabilities = []
        
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Build form URL
        if action:
            from urllib.parse import urljoin
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        req_timeout = aiohttp.ClientTimeout(total=4.0)

        # Test each input field
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            if not input_name:
                continue
            
            # Skip certain input types
            if input_field.get('type') in ['submit', 'button', 'hidden', 'file']:
                continue
            
            # Test with top payloads
            for payload in self.payloads[:3]:
                try:
                    form_data = {}
                    for inp in form.get('inputs', []):
                        inp_name = inp.get('name')
                        if inp_name:
                            if inp_name == input_name:
                                form_data[inp_name] = payload
                            else:
                                form_data[inp_name] = inp.get('value', 'test')
                    
                    if method == 'POST':
                        async with self.session.post(form_url, data=form_data, timeout=req_timeout) as response:
                            content = await response.text()
                    else:
                        async with self.session.get(form_url, params=form_data, timeout=req_timeout) as response:
                            content = await response.text()
                    
                    # Perform context-aware reflection analysis
                    analysis = self._analyze_reflection_context(payload, content)
                    
                    if analysis['status'] == 'rejected':
                        continue  # Payload was safely encoded, not vulnerable
                    
                    vuln = {
                        'type': 'xss',
                        'url': form_url,
                        'method': method,
                        'parameter': input_name,
                        'payload': payload,
                        'evidence': analysis['evidence'],
                        'description': f'XSS {analysis["status"]} in form parameter "{input_name}"',
                        'detection_reason': analysis['reason'],
                        'remediation': 'Implement proper input validation and output encoding',
                        'cwe': 'CWE-79',
                        'owasp': 'A03:2021 - Injection',
                        'verification_status': analysis['status'],
                        'reflection_context': analysis['context'],
                        'needs_browser_verification': analysis['needs_browser_verification'],
                        'severity': 'medium',
                        'confidence': 'Medium',
                    }
                    vulnerabilities.append(vuln)
                    break  # Found reflection, move to next parameter
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def _scan_url_param(self, url: str, param: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URL parameter for XSS with context-aware analysis."""
        import aiohttp
        vulnerabilities = []
        
        param_name = param.get('name')
        if not param_name:
            return vulnerabilities
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        req_timeout = aiohttp.ClientTimeout(total=4.0)
        
        for payload in self.payloads[:3]:
            try:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                async with self.session.get(test_url, timeout=req_timeout) as response:
                    content = await response.text()
                
                analysis = self._analyze_reflection_context(payload, content)
                
                if analysis['status'] == 'rejected':
                    continue
                
                vuln = {
                    'type': 'xss',
                    'url': test_url,
                    'method': 'GET',
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': analysis['evidence'],
                    'description': f'XSS {analysis["status"]} in URL parameter "{param_name}"',
                    'detection_reason': analysis['reason'],
                    'remediation': 'Implement proper input validation and output encoding',
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection',
                    'verification_status': analysis['status'],
                    'reflection_context': analysis['context'],
                    'needs_browser_verification': analysis['needs_browser_verification'],
                    'severity': 'medium',
                    'confidence': 'Medium',
                }
                vulnerabilities.append(vuln)
                break
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _analyze_reflection_context(self, payload: str, content: str) -> Dict[str, Any]:
        """Analyze where and how a payload is reflected in the response.
        
        Context analysis pipeline:
          1. Check if payload is reflected at all
          2. Determine the context of reflection (HTML body, attribute, script, comment)
          3. Check if reflection is safely encoded
          4. Assign verification status:
             - 'rejected'   — payload not reflected or safely encoded
             - 'potential'   — reflected in potentially executable context,
                              needs browser verification to confirm
        
        NEVER returns 'confirmed' — only actual browser execution confirms XSS.
        """
        result = {
            'status': 'rejected',
            'context': 'not_reflected',
            'reason': 'Payload not found in response',
            'evidence': '',
            'needs_browser_verification': False,
        }
        
        # Step 1: Check for any reflection
        if payload not in content:
            # Check if HTML-encoded version is present (safely encoded)
            encoded = html.escape(payload)
            if encoded in content:
                result['context'] = 'html_encoded'
                result['reason'] = 'Payload reflected but HTML-entity-encoded (safely neutralized)'
                result['evidence'] = self._extract_context_evidence(encoded, content)
                # Safely encoded = rejected, not a vulnerability
                return result
            # No reflection at all
            return result
        
        # Step 2: Extract the surrounding context of the reflection
        evidence_text = self._extract_context_evidence(payload, content)
        result['evidence'] = evidence_text
        
        # Step 3: Determine the context
        context_info = self._determine_context(payload, content)
        result['context'] = context_info['context']
        
        # Step 4: Evaluate executability based on context
        if context_info['context'] == 'html_comment':
            # Inside HTML comment — not executable
            result['status'] = 'rejected'
            result['reason'] = 'Payload reflected inside HTML comment (not executable)'
            return result
        
        if context_info['context'] == 'html_encoded_body':
            # Reflected but entities are encoded in body text
            result['status'] = 'rejected'
            result['reason'] = 'Payload reflected but HTML entities are encoded in body context'
            return result
        
        if context_info['context'] == 'html_body_unescaped':
            # Unescaped reflection in HTML body — potentially executable
            result['status'] = 'potential'
            result['reason'] = (
                'Payload reflected unescaped in HTML body context. '
                'Browser verification needed to confirm execution.'
            )
            result['needs_browser_verification'] = True
            return result
        
        if context_info['context'] == 'html_attribute_breakout':
            # Payload breaks out of an HTML attribute
            result['status'] = 'potential'
            result['reason'] = (
                'Payload appears to break out of an HTML attribute context. '
                'Browser verification needed to confirm execution.'
            )
            result['needs_browser_verification'] = True
            return result
        
        if context_info['context'] == 'script_block':
            # Inside a <script> block unescaped
            result['status'] = 'potential'
            result['reason'] = (
                'Payload reflected inside a JavaScript/script block. '
                'Browser verification needed to confirm execution.'
            )
            result['needs_browser_verification'] = True
            return result
        
        if context_info['context'] == 'event_handler':
            # Inside an event handler attribute
            result['status'] = 'potential'
            result['reason'] = (
                'Payload reflected in an event handler attribute context. '
                'Browser verification needed to confirm execution.'
            )
            result['needs_browser_verification'] = True
            return result
        
        # Default: payload is reflected but context is ambiguous
        result['status'] = 'potential'
        result['reason'] = (
            'Payload reflected in response but execution context is ambiguous. '
            'Browser verification needed to confirm execution.'
        )
        result['needs_browser_verification'] = True
        return result
    
    def _determine_context(self, payload: str, content: str) -> Dict[str, str]:
        """Determine the HTML/JS context where the payload is reflected."""
        try:
            idx = content.index(payload)
        except ValueError:
            return {'context': 'not_reflected'}
        
        # Get surrounding content for analysis
        before = content[max(0, idx - 500):idx]
        after = content[idx + len(payload):idx + len(payload) + 200]
        
        # Check if inside HTML comment
        last_comment_open = before.rfind('<!--')
        last_comment_close = before.rfind('-->')
        if last_comment_open > last_comment_close:
            return {'context': 'html_comment'}
        
        # Check if inside <script> block
        last_script_open = before.lower().rfind('<script')
        last_script_close = before.lower().rfind('</script')
        if last_script_open > last_script_close:
            return {'context': 'script_block'}
        
        # Check if inside an HTML attribute
        # Look for patterns like: attribute="...PAYLOAD..." or attribute='...PAYLOAD...'
        attr_double = before.rfind('"')
        attr_single = before.rfind("'")
        last_gt = before.rfind('>')
        last_lt = before.rfind('<')
        
        # We're inside a tag if the last < is after the last >
        if last_lt > last_gt:
            tag_content = before[last_lt:]
            # Check for event handler attributes
            event_handlers = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus',
                            'onblur', 'onsubmit', 'onchange', 'oninput', 'onkeydown',
                            'onkeyup', 'onmousedown', 'onmouseup']
            tag_lower = tag_content.lower()
            for handler in event_handlers:
                if handler in tag_lower:
                    return {'context': 'event_handler'}
            
            # Check if payload contains attribute-breaking characters
            if '">' in payload or "'>" in payload or payload.startswith('>'):
                return {'context': 'html_attribute_breakout'}
            
            # Inside a tag attribute but not breaking out
            return {'context': 'html_attribute'}
        
        # Check if the payload contains unescaped HTML-significant characters
        # that made it into the body
        if '<' in payload and payload in content:
            # The < character was not encoded — unescaped in body
            encoded_check = html.escape(payload)
            if encoded_check not in content:
                return {'context': 'html_body_unescaped'}
            else:
                return {'context': 'html_encoded_body'}
        
        # Generic body reflection — payload is in body but has no HTML significance
        return {'context': 'html_body_text'}
    
    def _extract_context_evidence(self, payload: str, content: str, context_length: int = 150) -> str:
        """Extract evidence showing the reflection context."""
        try:
            index = content.index(payload)
            start = max(0, index - context_length)
            end = min(len(content), index + len(payload) + context_length)
            snippet = content[start:end]
            return f"Reflection context:\n{snippet}"
        except ValueError:
            return "Payload not found in response"
