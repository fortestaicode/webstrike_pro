"""
Stealth Manager - Advanced Anti-Detection & Anti-WAF
Aggressive stealth techniques to avoid detection
"""
import random
import asyncio
from typing import Dict, Optional, List
from fake_useragent import UserAgent

class StealthManager:
    def __init__(self, 
                 aggressive: bool = True,
                 jitter_min: float = 0.5,
                 jitter_max: float = 3.0,
                 rotate_every: int = 5):
        """
        aggressive: Enable maximum stealth techniques
        jitter: Random delay between requests
        rotate_every: Rotate identity every X requests
        """
        self.aggressive = aggressive
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.rotate_every = rotate_every
        self.request_count = 0
        self.last_request_time = 0
        
        # Diverse browser types
        self.ua = UserAgent()
        self.current_identity = self._generate_identity()
        
    def _generate_identity(self) -> Dict:
        """Generate new browsing identity"""
        ua = self.ua.random
        
        identity = {
            "User-Agent": ua,
            "Accept": self._generate_accept_header(ua),
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.7",
                "fr-FR,fr;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8"
            ]),
            "Accept-Encoding": random.choice([
                "gzip, deflate, br", "gzip, deflate", "br;q=1.0, gzip;q=0.8"
            ]),
            "DNT": random.choice(["1", "0"]),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate", 
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Cache-Control": random.choice(["max-age=0", "no-cache", "no-store"]),
            "Referer": self._generate_referer(),
        }
        
        # Additional headers for aggressive mode
        if self.aggressive:
            identity.update({
                "X-Forwarded-For": self._generate_fake_ip(),
                "X-Real-IP": self._generate_fake_ip(),
                "X-Remote-IP": self._generate_fake_ip(),
                "X-Client-IP": self._generate_fake_ip(),
                "X-Host": self._generate_fake_ip(),
                "X-Forwarded-Host": self._generate_fake_ip(),
            })
        
        return {k: v for k, v in identity.items() if v is not None}
    
    def _generate_accept_header(self, ua: str) -> str:
        """Generate appropriate Accept header for UA"""
        if "Chrome" in ua:
            return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
        elif "Firefox" in ua:
            return "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        else:
            return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    
    def _generate_referer(self) -> str:
        """Generate random referer"""
        referers = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            "https://www.facebook.com/",
            "https://twitter.com/",
            "https://www.linkedin.com/",
            "https://www.reddit.com/",
            "https://www.youtube.com/",
        ]
        return random.choice(referers) + f"?q={random.randint(1000, 9999)}"
    
    def _generate_fake_ip(self) -> str:
        """Generate fake IP for X-Forwarded-For"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    async def apply_delay(self):
        """Apply random jitter delay"""
        delay = random.uniform(self.jitter_min, self.jitter_max)
        
        # Additional random delay in aggressive mode
        if self.aggressive and random.random() > 0.8:
            delay += random.uniform(1.0, 5.0)
        
        await asyncio.sleep(delay)
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers for next request"""
        self.request_count += 1
        
        # Rotate identity
        if self.request_count % self.rotate_every == 0:
            self.current_identity = self._generate_identity()
        
        return self.current_identity.copy()
    
    def rotate_identity(self):
        """Manually rotate identity"""
        self.current_identity = self._generate_identity()
        self.request_count = 0
    
    async def simulate_human_behavior(self, page_content: Optional[str] = None):
        """Simulate human reading behavior"""
        if page_content and len(page_content) > 1000:
            # Simulate reading time
            read_time = min(len(page_content) / 500, 10)
            await asyncio.sleep(read_time)
        else:
            await asyncio.sleep(random.uniform(2, 5))