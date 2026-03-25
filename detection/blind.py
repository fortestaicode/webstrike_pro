"""
Blind Detector - Detects blind vulnerabilities (time-based, boolean-based)
"""
import time
import asyncio
from typing import Dict, Optional, List

class BlindDetector:
    def __init__(self, engine):
        self.engine = engine
        self.time_threshold = 4.5  # Seconds
    
    async def detect_time_based(self, url: str, param: str, payloads: List[str]) -> Optional[Dict]:
        """Detect time-based blind injection"""
        for payload in payloads:
            start = time.time()
            result = await self._send_request(url, param, payload)
            elapsed = time.time() - start
            
            if elapsed > self.time_threshold:
                return {
                    "type": "BLIND_TIME_BASED",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "response_time": elapsed,
                    "severity": "CRITICAL"
                }
        return None
    
    async def detect_boolean_based(self, url: str, param: str, 
                                   true_payload: str, false_payload: str) -> Optional[Dict]:
        """Detect boolean-based blind injection"""
        result_true = await self._send_request(url, param, true_payload)
        result_false = await self._send_request(url, param, false_payload)
        
        # Compare responses
        diff = abs(len(result_true.body) - len(result_false.body))
        
        if diff > 100:  # Significant difference
            return {
                "type": "BLIND_BOOLEAN_BASED",
                "url": url,
                "parameter": param,
                "true_payload": true_payload,
                "false_payload": false_payload,
                "length_difference": diff,
                "severity": "CRITICAL"
            }
        return None
    
    async def _send_request(self, url: str, param: str, payload: str):
        """Send request with payload"""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        return await self.engine.request("GET", test_url)