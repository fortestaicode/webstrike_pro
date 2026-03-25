"""
Web Crawler - Advanced Async Web Crawler
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict, Optional
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self, engine, scope_guard, stealth_manager=None, max_depth: int = 3):
        self.engine = engine
        self.scope = scope_guard
        self.stealth = stealth_manager
        self.max_depth = max_depth
        
        self.visited: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.js_files: Set[str] = set()
        
    async def crawl(self, start_url: str) -> List[Dict]:
        """
        Start crawling from given URL
        """
        to_visit = [(start_url, 0)]
        results = []
        
        while to_visit:
            current_batch = []
            while to_visit and len(current_batch) < 10:
                url, depth = to_visit.pop(0)
                if url not in self.visited and depth <= self.max_depth:
                    current_batch.append((url, depth))
            
            if not current_batch:
                break
            
            tasks = [self._fetch_and_parse(url, depth) for url, depth in current_batch]
            batch_results = await asyncio.gather(*tasks)
            
            for result in batch_results:
                if result:
                    results.append(result)
                    for link in result.get("links", []):
                        if link not in self.visited:
                            to_visit.append((link, result["depth"] + 1))
        
        return results
    
    async def _fetch_and_parse(self, url: str, depth: int) -> Optional[Dict]:
        """Fetch and parse page"""
        if url in self.visited:
            return None
        
        self.visited.add(url)
        
        if self.stealth:
            await self.stealth.apply_delay()
        
        headers = self.stealth.get_headers() if self.stealth else {}
        result = await self.engine.request("GET", url, headers=headers)
        
        if result.status != 200 or not result.body:
            return None
        
        soup = BeautifulSoup(result.body, 'xml')
        
        links = self._extract_links(soup, url)
        links = self.scope.validate_urls(links)
        self.discovered_urls.update(links)
        
        forms = self._extract_forms(soup, url)
        self.forms.extend(forms)
        
        scripts = self._extract_scripts(soup, url)
        self.js_files.update(scripts)
        
        return {
            "url": url,
            "depth": depth,
            "status": result.status,
            "title": soup.title.string if soup.title else "",
            "links": links,
            "forms": forms,
            "scripts": scripts,
            "content_type": result.content_type
        }
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links"""
        links = []
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            full_url = urljoin(base_url, href)
            if self._is_valid_url(full_url):
                links.append(full_url)
        return list(set(links))
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Dict]:
        """Extract forms"""
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    "name": inp.get('name', ''),
                    "type": inp.get('type', 'text'),
                    "value": inp.get('value', '')
                })
            forms.append({
                "action": urljoin(page_url, action),
                "method": method,
                "inputs": inputs,
                "page": page_url
            })
        return forms
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract JavaScript files"""
        scripts = []
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.endswith('.js'):
                full_url = urljoin(base_url, src)
                scripts.append(full_url)
        return scripts
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL"""
        parsed = urlparse(url)
        return bool(parsed.scheme in ['http', 'https'] and parsed.netloc)
    
    def get_results(self) -> Dict:
        """Get all results"""
        return {
            "visited": list(self.visited),
            "discovered": list(self.discovered_urls),
            "forms": self.forms,
            "js_files": list(self.js_files)
        }
