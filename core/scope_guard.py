"""
Scope Guard - Advanced Scope Verification
Strict scope enforcement to prevent out-of-scope requests
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import Set, List, Optional
import tldextract

class ScopeGuard:
    def __init__(self, scope_targets: List[str], strict_mode: bool = True):
        """
        scope_targets: List of allowed targets (domains, IPs, CIDR, wildcards)
        strict_mode: If True, reject anything outside scope completely
        """
        self.strict_mode = strict_mode
        self.allowed_domains: Set[str] = set()
        self.allowed_ips: Set[ipaddress.ip_network] = set()
        self.wildcard_patterns: List[re.Pattern] = []
        self.excluded_targets: Set[str] = set()
        
        self._parse_scope(scope_targets)
    
    def _parse_scope(self, targets: List[str]):
        """Parse scope targets"""
        for target in targets:
            target = target.strip().lower()
            
            # Exclude targets (prefixed with -)
            if target.startswith('-'):
                self.excluded_targets.add(target[1:])
                continue
            
            # Wildcard domains (*.example.com)
            if target.startswith('*.'):
                domain = target[2:]
                pattern = re.compile(r'^(.*\.)?' + re.escape(domain) + r'$')
                self.wildcard_patterns.append(pattern)
                self.allowed_domains.add(domain)
            
            # IP ranges (CIDR)
            elif '/' in target:
                try:
                    self.allowed_ips.add(ipaddress.ip_network(target, strict=False))
                except ValueError:
                    pass
            
            # Single IP
            elif self._is_ip(target):
                self.allowed_ips.add(ipaddress.ip_network(target + '/32'))
            
            # Domain
            else:
                self.allowed_domains.add(target)
                # Add www variant
                if not target.startswith('www.'):
                    self.allowed_domains.add('www.' + target)
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if URL is within allowed scope
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            
            if not host:
                return False
            
            host = host.lower()
            
            # Check exclusions first
            if host in self.excluded_targets:
                return False
            
            # Check IPs
            if self._is_ip(host):
                ip = ipaddress.ip_address(host)
                for network in self.allowed_ips:
                    if ip in network:
                        return True
                return False if self.strict_mode else True
            
            # Check direct domains
            if host in self.allowed_domains:
                return True
            
            # Check wildcards
            for pattern in self.wildcard_patterns:
                if pattern.match(host):
                    return True
            
            # Check TLD
            extracted = tldextract.extract(url)
            registered_domain = f"{extracted.domain}.{extracted.suffix}"
            
            if registered_domain in self.allowed_domains:
                return True
            
            return False if self.strict_mode else True
            
        except Exception:
            return False
    
    def validate_urls(self, urls: List[str]) -> List[str]:
        """Filter list of URLs"""
        return [url for url in urls if self.is_in_scope(url)]
    
    def get_scope_summary(self) -> dict:
        """Return scope summary"""
        return {
            "domains": list(self.allowed_domains),
            "ip_ranges": [str(ip) for ip in self.allowed_ips],
            "wildcards": len(self.wildcard_patterns),
            "excluded": list(self.excluded_targets),
            "strict_mode": self.strict_mode
        }