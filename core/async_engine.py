"""
Async Engine - High Performance HTTP Engine
FFUF-level performance with async/await
"""
import asyncio
import aiohttp
import aiofiles
import aiodns
from asyncio_throttle import Throttler
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass
import time

@dataclass
class RequestResult:
    url: str
    status: int
    length: int
    content_type: str
    response_time: float
    headers: Dict
    body: Optional[str] = None
    error: Optional[str] = None
    matched: bool = False

class AsyncEngine:
    def __init__(self, 
                 threads: int = 50,
                 delay: float = 0.0,
                 timeout: int = 10,
                 retries: int = 5,
                 verify_ssl: bool = False,
                 follow_redirects: bool = True):
        """
        threads: Number of concurrent connections
        delay: Delay between requests
        timeout: Request timeout in seconds
        retries: Number of retries on failure
        """
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.retries = retries
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        
        self.throttler = Throttler(rate_limit=threads, period=1.0)
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "retries": 0
        }
        
    async def __aenter__(self):
        """Context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            limit_per_host=self.threads // 2,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.session:
            await self.session.close()
    
    async def request(self, 
                     method: str, 
                     url: str, 
                     headers: Optional[Dict] = None,
                     payload: Optional[str] = None,
                     allow_redirects: Optional[bool] = None) -> RequestResult:
        """
        Execute single HTTP request with retry logic
        """
        start_time = time.time()
        
        if allow_redirects is None:
            allow_redirects = self.follow_redirects
        
        for attempt in range(self.retries + 1):
            try:
                async with self.throttler:
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    
                    async with self.session.request(
                        method=method,
                        url=url,
                        headers=headers,
                        data=payload,
                        allow_redirects=allow_redirects,
                        ssl=self.verify_ssl,
                    ) as response:
                        
                        body = await response.text()
                        elapsed = time.time() - start_time
                        
                        self.stats["success"] += 1
                        
                        return RequestResult(
                            url=url,
                            status=response.status,
                            length=len(body),
                            content_type=response.headers.get('Content-Type', ''),
                            response_time=elapsed,
                            headers=dict(response.headers),
                            body=body,
                            matched=True if response.status in [200, 204, 301, 302, 307, 401, 403, 405] else False
                        )
                        
            except asyncio.TimeoutError:
                if attempt == self.retries:
                    self.stats["failed"] += 1
                    return RequestResult(
                        url=url,
                        status=0,
                        length=0,
                        content_type="",
                        response_time=time.time() - start_time,
                        headers={},
                        error="Timeout",
                        matched=False
                    )
                self.stats["retries"] += 1
                await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
                
            except Exception as e:
                if attempt == self.retries:
                    self.stats["failed"] += 1
                    return RequestResult(
                        url=url,
                        status=0,
                        length=0,
                        content_type="",
                        response_time=time.time() - start_time,
                        headers={},
                        error=str(e),
                        matched=False
                    )
                self.stats["retries"] += 1
                await asyncio.sleep(0.5)
        
        self.stats["failed"] += 1
        return RequestResult(url=url, status=0, length=0, content_type="", 
                           response_time=0, headers={}, error="Max retries exceeded")
    
    async def bulk_requests(self, 
                           urls: List[str], 
                           method: str = "GET",
                           headers: Optional[Dict] = None,
                           callback: Optional[Callable[[RequestResult], Any]] = None) -> List[RequestResult]:
        """
        Execute multiple requests concurrently (FFUF-style)
        """
        self.stats["total"] += len(urls)
        
        semaphore = asyncio.Semaphore(self.threads)
        
        async def bound_request(url):
            async with semaphore:
                result = await self.request(method, url, headers)
                if callback:
                    await callback(result)
                return result
        
        tasks = [bound_request(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, RequestResult)]
    
    async def fuzz_directory(self, 
                            base_url: str, 
                            wordlist: List[str],
                            extensions: List[str] = None,
                            headers: Optional[Dict] = None,
                            hide_status: List[int] = None,
                            show_status: List[int] = None,
                            filter_length: Optional[int] = None) -> List[RequestResult]:
        """
        Directory fuzzing with FFUF-level performance
        """
        urls = []
        for word in wordlist:
            urls.append(f"{base_url}/{word}")
            if extensions:
                for ext in extensions:
                    urls.append(f"{base_url}/{word}.{ext}")
        
        results = await self.bulk_requests(urls, headers=headers)
        
        # Filter results
        filtered = []
        for res in results:
            if hide_status and res.status in hide_status:
                continue
            if show_status and res.status not in show_status:
                continue
            if filter_length and res.length == filter_length:
                continue
            filtered.append(res)
        
        return filtered
    
    def get_stats(self) -> Dict:
        """Performance statistics"""
        return self.stats.copy()
