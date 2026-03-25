"""
Hidden Scanner - Intelligent Brute-force with Smart Wordlists
Detects both files AND directories
"""
import asyncio
from typing import List, Dict, Set, Optional

class HiddenScanner:
    def __init__(self, engine, scope_guard, waf_evasion=None, custom_wordlist: str = None):
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
            "directories": self._load_directory_wordlist(),  # ✅ جديد: قائمة المجلدات
        }

        # Load custom wordlist if provided
        if custom_wordlist:
            self.wordlists["custom"] = self._load_wordlist_file(custom_wordlist)

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
            '.env', '.env.local', '.env.production', '.env.development', '.env.backup',
            'config.php', 'config.json', 'config.yaml', 'config.yml', 'config.xml',
            'configuration.php', 'settings.php', 'database.php', 'wp-config.php',
            'wp-config.php.bak', 'wp-config.php~', 'wp-config.old',
            '.htaccess', '.htpasswd', 'web.config', 'nginx.conf',
            'docker-compose.yml', 'Dockerfile', '.dockerignore',
            'package.json', 'composer.json', 'requirements.txt',
        ]

    def _load_api_wordlist(self) -> List[str]:
        """API endpoints"""
        return [
            'api', 'api/v1', 'api/v2', 'api/v3', 'api/docs', 'api/swagger',
            'swagger', 'swagger-ui', 'swagger.json', 'swagger.yaml',
            'openapi.json', 'openapi.yaml', 'graphql', 'graphiql',
            'api/graphql', 'query', 'mutation', 'subscription',
            '.well-known/openid-configuration', '.well-known/security.txt',
        ]

    def _load_admin_wordlist(self) -> List[str]:
        """Admin panels"""
        return [
            'admin', 'administrator', 'admin.php', 'admin/login.php',
            'admin/login', 'adminpanel', 'controlpanel', 'cp', 'panel',
            'login', 'login.php', 'signin', 'auth', 'auth.php',
            'dashboard', 'backend', 'manage', 'manager', 'adminarea',
            'phpmyadmin', 'pma', 'myadmin', 'dbadmin', 'mysql',
            'wp-admin', 'wp-login', 'wp-login.php',
        ]

    def _load_vcs_wordlist(self) -> List[str]:
        """Version control systems"""
        return [
            '.git', '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
            '.gitignore', '.gitattributes', '.gitmodules',
            '.svn', '.svn/entries', '.svn/wc.db',
            '.hg', '.hg/store', '.bzr', 'CVS',
            '.DS_Store', 'Thumbs.db',
        ]

    def _load_cloud_wordlist(self) -> List[str]:
        """Cloud integrations"""
        return [
            '.aws', '.azure', 'gcp', '.terraform',
            '.env.aws', 'credentials.json', 'service-account.json',
            '.kube', '.kube/config', 'k8s', 'kubernetes',
        ]

    def _load_directory_wordlist(self) -> List[str]:
        """✅ جديد: Common directories to brute force"""
        return [
            'api', 'admin', 'dashboard', 'panel', 'manage', 'manager',
            'uploads', 'upload', 'files', 'file', 'docs', 'documents',
            'backup', 'backups', 'bak', 'old', 'archive', 'archives',
            'config', 'configuration', 'settings', 'env',
            'test', 'tests', 'staging', 'dev', 'development',
            'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql',
            'swagger', 'docs', 'documentation', 'help',
            'internal', 'private', 'restricted', 'secret',
            'logs', 'log', 'tmp', 'temp', 'cache',
            'assets', 'static', 'media', 'images', 'img',
            'js', 'javascript', 'css', 'styles', 'fonts',
            'vendor', 'vendors', 'node_modules', 'bower_components',
            'includes', 'include', 'inc', 'lib', 'library', 'libraries',
            'classes', 'class', 'modules', 'module', 'controllers',
            'models', 'views', 'templates', 'template', 'themes',
            'data', 'database', 'db', 'sql', 'mysql', 'postgres',
            'wp-content', 'wp-includes', 'wp-admin',
        ]

    def _load_wordlist_file(self, filepath: str) -> List[str]:
        """Load custom wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"[+] Loaded {len(words)} words from {filepath}")
            return words
        except Exception as e:
            print(f"[!] Failed to load wordlist {filepath}: {e}")
            return []

    async def scan(self, base_url: str, categories: List[str] = None) -> List[Dict]:
        """
        Comprehensive hidden file and directory scan
        """
        if categories is None:
            categories = ["backup", "config", "api", "admin", "vcs", "directories"]  # ✅ أضفنا directories

        all_results = []

        for category in categories:
            if category not in self.wordlists:
                continue

            wordlist = self.wordlists[category]

            # ✅ بناء URLs مع التمييز بين files و directories
            urls = []
            for word in wordlist:
                # إذا كان بدون extension (احتمال directory)
                if '.' not in word or word.startswith('.'):
                    # جرب بدون / أولاً (للتأكد)
                    urls.append(f"{base_url}/{word}")
                    # ثم جرب مع / (كـ directory)
                    urls.append(f"{base_url}/{word}/")
                else:
                    urls.append(f"{base_url}/{word}")

            # Validate scope
            urls = self.scope.validate_urls(urls)

            print(f"[HiddenScanner] Scanning {category}: {len(urls)} URLs")

            results = await self.engine.bulk_requests(urls)

            for res in results:
                # ✅ التحقق مما إذا كان directory (ينتهي بـ /)
                is_directory = res.url.endswith('/')

                if res.status in [200, 201, 204, 301, 302, 307, 308, 401, 403, 407]:
                    # ✅ تحقق إضافي للـ directories
                    if is_directory and res.status == 200:
                        # تحقق من وجود directory listing
                        if self._is_directory_listing(res.body):
                            risk = "HIGH"
                        else:
                            risk = "MEDIUM"
                    elif is_directory and res.status in [301, 302, 307, 308]:
                        # Redirect مع / يعني directory موجود
                        risk = "MEDIUM"
                    else:
                        risk = self._assess_risk(res.url, category, res.status)

                    finding = {
                        "url": res.url.rstrip('/') if not is_directory else res.url,  # احتفظ بـ / للـ directories
                        "status": res.status,
                        "length": res.length,
                        "category": category,
                        "risk": risk,
                        "is_directory": is_directory,
                        "content_type": res.content_type
                    }

                    if risk in ["CRITICAL", "HIGH"]:
                        self.critical_findings.append(finding)

                    all_results.append(finding)
                    self.found_paths.add(res.url)

        return all_results

    def _is_directory_listing(self, body: str) -> bool:
        """✅ جديد: التحقق مما إذا كان المحتوى directory listing"""
        if not body:
            return False

        indicators = [
            '<title>Index of ',
            'Directory Listing',
            'Parent Directory',
            'Last modified</a>',
            'Size</a>',
            'Description</a>',
            '<h1>Index of /',
            'Apache/2',
            'nginx/',
        ]

        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                return True

        # التحقق من وجود روابط لملفات في الصفحة (عادة ما يكون في directory listing)
        import re
        file_links = re.findall(r'href="([^"]+)"', body)
        if len(file_links) > 3:
            return True

        return False

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

        if category == "directories":
            if any(x in url_lower for x in ['admin', 'backup', 'config', '.env']):
                return "HIGH"
            return "MEDIUM"

        if status == 403:
            return "MEDIUM"

        if status == 200:
            return "LOW"

        return "INFO"

    def get_critical_findings(self) -> List[Dict]:
        """Get critical findings"""
        return self.critical_findings
