"""
Reflected Detector - Detects reflected input in responses
"""
import urllib.parse
from typing import Dict, Optional, List

class ReflectedDetector:
    def __init__(self, engine):
        self.engine = engine
        self.markers = [
            "REFLECTED_{random}",
            "<b>TEST</b>",
            "'\"/><script>",
        ]
    
    async def detect(self, url: str, param: str) -> Optional[Dict]:
        """Detect if parameter is reflected in response"""
        marker = f"REFLECT_{hash(url + param) % 10000}"
        
        # Inject marker
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [marker]
        new_query = urllib.parse.urlencode(params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        result = await self.engine.request("GET", test_url)
        
        if result.body and marker in result.body:
            # Determine context
            context = self._get_context(result.body, marker)
            
            return {
                "type": "REFLECTED_PARAMETER",
                "url": url,
                "parameter": param,
                "marker": marker,
                "context": context,
                "severity": "MEDIUM",
                "exploitable": context in ["html", "attribute", "script"]
            }
        
        return None
    
    def _get_context(self, body: str, marker: str) -> str:
        """Determine reflection context"""
        idx = body.find(marker)
        if idx == -1:
            return "unknown"
        
        # Check surrounding context
        before = body[max(0, idx-50):idx]
        after = body[idx+len(marker):min(len(body), idx+len(marker)+50)]
        
        if "<script" in before.lower():
            return "script"
        elif "=" in before and '"' in before:
            return "attribute"
        elif "<" in before:
            return "html"
        else:
            return "text"