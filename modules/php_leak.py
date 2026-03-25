"""
PHP Leak Detector - Advanced PHP Source Code Exposure Detection
"""
import re
from typing import Dict, List, Optional, Tuple

class PHPLeakDetector:
    def __init__(self):
        self.php_signatures = {
            "tags": [b"<?php", b"<?=", b"<?\n", b"<?\r"],
            "functions": [
                b"function ", b"class ", b"namespace ", b"use ",
                b"echo ", b"print_r(", b"var_dump(", b"include(",
                b"require(", b"include_once(", b"require_once(",
                b"mysql_connect(", b"mysqli_", b"PDO::", b"$this->",
            ],
            "variables": [b"$_GET", b"$_POST", b"$_REQUEST", b"$_SESSION", 
                         b"$_COOKIE", b"$_SERVER", b"$GLOBALS"],
            "config_indicators": [
                b"DB_HOST", b"DB_USER", b"DB_PASS", b"DB_NAME",
                b"database_password", b"mysql_password", b"admin_password",
                b"SECRET_KEY", b"API_KEY", b"AUTH_TOKEN",
            ]
        }
        
        self.backup_extensions = [
            '.php~', '.php.bak', '.php.old', '.php.swp', '.php.save',
            '.php.txt', '.php.zip', '.php.gz', '.php.tar.gz',
            '.php.rar', '.php.7z', '.php.copy', '.php.orig',
            '.php_', '.php1', '.php2',
        ]
    
    async def check_endpoint(self, engine, url: str) -> Optional[Dict]:
        """
        Check endpoint for PHP leak
        """
        # Check if URL ends with backup extensions
        is_backup = any(url.lower().endswith(ext) for ext in self.backup_extensions)
        
        if not is_backup and not url.lower().endswith('.php'):
            return None
        
        result = await engine.request("GET", url)
        
        if result.status != 200 or not result.body:
            return None
        
        body_bytes = result.body.encode() if isinstance(result.body, str) else result.body
        
        leak_info = self._analyze_content(body_bytes, url)
        
        if leak_info["is_php_leak"]:
            return {
                "url": url,
                "type": "PHP_SOURCE_LEAK",
                "confidence": leak_info["confidence"],
                "indicators_found": leak_info["indicators"],
                "severity": "CRITICAL" if leak_info["has_credentials"] else "HIGH",
                "snippet": leak_info["snippet"],
                "size": len(body_bytes)
            }
        
        return None
    
    def _analyze_content(self, content: bytes, url: str) -> Dict:
        """Analyze content for PHP"""
        indicators = []
        confidence = 0
        has_credentials = False
        
        # Check PHP tags
        for tag in self.php_signatures["tags"]:
            if tag in content[:5000]:
                indicators.append(f"PHP_TAG: {tag.decode(errors='ignore')}")
                confidence += 40
                break
        
        # Check functions
        func_count = 0
        for func in self.php_signatures["functions"]:
            if func in content:
                func_count += 1
        
        if func_count >= 3:
            indicators.append(f"PHP_FUNCTIONS: {func_count} found")
            confidence += 30
        
        # Check global variables
        var_count = 0
        for var in self.php_signatures["variables"]:
            if var in content:
                var_count += 1
        
        if var_count >= 2:
            indicators.append(f"PHP_VARS: {var_count} found")
            confidence += 20
        
        # Check credentials
        for indicator in self.php_signatures["config_indicators"]:
            if indicator in content:
                indicators.append(f"CREDENTIAL: {indicator.decode()}")
                has_credentials = True
                confidence += 50
        
        # Extract snippet
        snippet = ""
        if b"<?php" in content:
            start = content.find(b"<?php")
            snippet = content[start:start+200].decode(errors='replace')
        
        return {
            "is_php_leak": confidence >= 50,
            "confidence": min(confidence, 100),
            "indicators": indicators,
            "has_credentials": has_credentials,
            "snippet": snippet
        }
    
    def generate_backup_urls(self, base_url: str) -> List[str]:
        """Generate potential backup URLs"""
        if not base_url.endswith('.php'):
            return []
        
        urls = []
        for ext in self.backup_extensions:
            urls.append(base_url + ext)
        
        # Add other common patterns
        base = base_url.replace('.php', '')
        urls.extend([
            f"{base}.php.bak",
            f"{base}.php.old", 
            f"{base}.php~",
            f"{base}_backup.php",
            f"{base}.copy.php",
            f"copy_of_{base_url}",
        ])
        
        return urls
    
    async def scan_directory(self, engine, base_url: str, common_files: List[str]) -> List[Dict]:
        """Scan directory for PHP leaks"""
        findings = []
        
        for file in common_files:
            if not file.endswith('.php'):
                continue
            
            url = f"{base_url}/{file}"
            backup_urls = self.generate_backup_urls(url)
            
            for backup_url in backup_urls:
                result = await self.check_endpoint(engine, backup_url)
                if result:
                    findings.append(result)
        
        return findings