"""
Hidden Scanner - Intelligent Brute-force with Smart Wordlists
"""
import asyncio
from typing import List, Dict, Set, Optional

class HiddenScanner:
    def __init__(self, engine, scope_guard, waf_evasion=None):
        self.engine = engine
        self.scope = scope_guard
        self.waf = waf_evasion
        
        # Specialized wordlists
        self.wordlists = {
            "backup": self._load_backup_wordlist(),
            "config": self._load_config_wordlist(),
            "api": self._load_api_wordlist(),
            "admin": self._load_admin_wordlist(),
            "vcs": self._load_vcs_wordlist(),
            "cloud": self._load_cloud_wordlist(),
        }
        
        self.found_paths: Set[str] = set()
        self.critical_findings: List[Dict] = []
        
    def _load_backup_wordlist(self) -> List[str]:
        """Backup file wordlist"""
        extensions = ['.bak', '.old', '.orig', '.save', '.swp', '.tmp', 
                     '.backup', '.copy', '~', '.zip', '.tar.gz', '.rar', '.7z']
        files = ['index', 'backup', 'dump', 'database', 'db', 'site', 'www', 'public_html']
        
        wordlist = []
        for file in files:
            for ext in extensions:
                wordlist.append(f"{file}{ext}")
                wordlist.append(f"{file.upper()}{ext}")
        return wordlist
    
    def _load_config_wordlist(self) -> List[str]:
        """Sensitive configuration files"""
        return [
            ".env", ".env.local", ".env.production", ".env.development", ".env.backup",
            "config.php", "config.json", "config.yaml", "config.yml", "config.xml",
            "configuration.php", "settings.php", "database.php", "wp-config.php",
            "wp-config.php.bak", "wp-config.php~", "wp-config.old",
            ".htaccess", ".htpasswd", "web.config", "nginx.conf",
            "docker-compose.yml", "Dockerfile", ".dockerignore",
            "package.json", "composer.json", "requirements.txt",
        ]
    
    def _load_api_wordlist(self) -> List[str]:
        """API endpoints"""
        return [
            "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
            "swagger", "swagger-ui", "swagger.json", "swagger.yaml",
            "openapi.json", "openapi.yaml", "graphql", "graphiql",
            "api/graphql", "query", "mutation", "subscription",
            ".well-known/openid-configuration", ".well-known/security.txt",
        ]
    
    def _load_admin_wordlist(self) -> List[str]:
        """Admin panels"""
        return [
            "admin", "administrator", "admin.php", "admin/login.php",
            "admin/login", "adminpanel", "controlpanel", "cp", "panel",
            "login", "login.php", "signin", "auth", "auth.php",
            "dashboard", "backend", "manage", "manager", "adminarea",
            "phpmyadmin", "pma", "myadmin", "dbadmin", "mysql",
            "wp-admin", "wp-login", "wp-login.php",
        ]
    
    def _load_vcs_wordlist(self) -> List[str]:
        """Version control systems"""
        return [
            ".git", ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
            ".gitignore", ".gitattributes", ".gitmodules",
            ".svn", ".svn/entries", ".svn/wc.db",
            ".hg", ".hg/store", ".bzr", "CVS",
            ".DS_Store", "Thumbs.db",
        ]
    
    def _load_cloud_wordlist(self) -> List[str]:
        """Cloud integrations"""
        return [
            ".aws", ".azure", "gcp", ".terraform",
            ".env.aws", "credentials.json", "service-account.json",
            ".kube", ".kube/config", "k8s", "kubernetes",
        ]
    
    async def scan(self, base_url: str, categories: List[str] = None) -> List[Dict]:
        """
        Comprehensive hidden file scan
        """
        if categories is None:
            categories = ["backup", "config", "api", "admin", "vcs"]
        
        all_results = []
        
        for category in categories:
            if category not in self.wordlists:
                continue
            
            wordlist = self.wordlists[category]
            urls = [f"{base_url}/{word}" for word in wordlist]
            
            # Validate scope
            urls = self.scope.validate_urls(urls)
            
            print(f"[HiddenScanner] Scanning {category}: {len(urls)} URLs")
            
            results = await self.engine.bulk_requests(urls)
            
            for res in results:
                if res.status in [200, 201, 204, 301, 302, 307, 308, 401, 403, 407]:
                    risk = self._assess_risk(res.url, category, res.status)
                    finding = {
                        "url": res.url,
                        "status": res.status,
                        "length": res.length,
                        "category": category,
                        "risk": risk,
                        "content_type": res.content_type
                    }
                    
                    if risk in ["CRITICAL", "HIGH"]:
                        self.critical_findings.append(finding)
                    
                    all_results.append(finding)
                    self.found_paths.add(res.url)
        
        return all_results
    
    def _assess_risk(self, url: str, category: str, status: int) -> str:
        """Assess finding risk"""
        url_lower = url.lower()
        
        if category == "config":
            if any(x in url_lower for x in ['.env', 'wp-config', 'credentials', 'password']):
                return "CRITICAL"
            if status == 200:
                return "HIGH"
        
        if category == "backup":
            if any(x in url_lower for x in ['.sql', '.dump', 'database']):
                return "CRITICAL"
            return "HIGH"
        
        if category == "vcs" and ".git" in url_lower:
            return "CRITICAL"
        
        if status == 403:
            return "MEDIUM"
        
        if status == 200:
            return "LOW"
        
        return "INFO"
    
    def get_critical_findings(self) -> List[Dict]:
        """Get critical findings"""
        return self.critical_findings