#!/usr/bin/env python3
"""
WebStrike Pro - Advanced Web Security Testing Platform
⚠️  WARNING: For authorized security testing only!
"""
import asyncio
import argparse
import sys
import os
import aiofiles
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from core.async_engine import AsyncEngine
from core.scope_guard import ScopeGuard
from core.stealth_manager import StealthManager
from core.waf_evasion import WAFEvasion
from modules.crawler import Crawler
from modules.hidden_scanner import HiddenScanner
from modules.php_leak import PHPLeakDetector
from modules.js_analyzer import JSAnalyzer
from detection.xss_scanner import XSSScanner
from detection.sqli_scanner import SQLiScanner
from integrations.nuclei import NucleiIntegration
from utils.reporter import Reporter
from modules.xml_analyzer import XMLAnalyzer


async def download_files(engine, urls, base_url: str, output_dir: str, max_files: int = 1000):
    """Download discovered files preserving directory structure"""
    base_parsed = urlparse(base_url)
    base_netloc = base_parsed.netloc.replace(":", "_")

    download_dir = Path(output_dir) / "downloads" / base_netloc
    download_dir.mkdir(parents=True, exist_ok=True)

    downloaded_count = 0
    downloaded_files = []

    for url in urls[:max_files]:
        try:
            result = await engine.request("GET", url)
            if result and hasattr(result, 'status') and result.status == 200 and result.body:
                parsed = urlparse(url)
                relative_path = parsed.path.lstrip('/')

                safe_parts = []
                for part in relative_path.split('/'):
                    if part in ('..', '.') or part.upper() in ('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'LPT1'):
                        part = f"_{part}"
                    safe_parts.append(part)

                safe_path = '/'.join(safe_parts) if safe_parts else "index.html"
                local_path = download_dir / safe_path
                local_path.parent.mkdir(parents=True, exist_ok=True)

                content = result.body
                if isinstance(content, str):
                    async with aiofiles.open(local_path, 'w', encoding='utf-8') as f:
                        await f.write(content)
                else:
                    async with aiofiles.open(local_path, 'wb') as f:
                        await f.write(content)

                downloaded_count += 1
                downloaded_files.append({
                    "url": url,
                    "local_path": str(local_path),
                    "size": len(content) if isinstance(content, bytes) else len(content.encode())
                })
                print(f"  [+] Downloaded: {url}")

        except Exception as e:
            if "-v" in sys.argv or "--verbose" in sys.argv:
                print(f"  [!] Failed: {url}: {e}")

    print(f"\n[+] Total downloaded: {downloaded_count} files")
    return downloaded_files


def is_in_scope(url: str, scope_targets: list) -> bool:
    """Check if URL is within scope - STRICT CHECKING"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    for scope in scope_targets:
        scope_clean = scope.replace("*.", "").lower()

        # تطابق تام
        if hostname_lower == scope_clean:
            return True
        # نطاق فرعي (مثل *.example.com)
        if scope.startswith("*.") and hostname_lower.endswith(scope_clean):
            return True
        # يحتوي على (للـ IP addresses)
        if scope_clean in hostname_lower:
            return True
    return False


def filter_cdn_urls(urls: list, scope_targets: list) -> list:
    """Filter out CDN URLs and external domains"""
    cdn_patterns = [
        'cdnjs.cloudflare.com', 'sdk.amazonaws.com', 'cdn.jsdelivr.net', 
        'ajax.googleapis.com', 'code.jquery.com', 'maxcdn.bootstrapcdn.com',
        'unpkg.com', 'cdnjs.com', 'jsdelivr.net', 'bootstrapcdn.com',
        'cloudflare.com', 'googleapis.com', 'gstatic.com', 'fbcdn.net',
        'akamaihd.net', 'cloudfront.net', 'fastly.net'
    ]

    filtered = []
    for url in urls:
        # فحص CDN patterns
        if any(cdn in url for cdn in cdn_patterns):
            continue
        # فحص Scope الصارم
        if is_in_scope(url, scope_targets):
            filtered.append(url)
    return filtered


async def main():
    parser = argparse.ArgumentParser(
        description="WebStrike Pro - Advanced Web Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u https://example.com --full
  python main.py -u https://example.com --full --download
  python main.py -u https://example.com --crawl --hidden -o reports
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--scope", nargs="+", help="Scope targets")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--waf-evasion", choices=["basic", "aggressive"], help="WAF evasion")
    parser.add_argument("--full", action="store_true", help="Enable all scan modules")
    parser.add_argument("--crawl", action="store_true", help="Enable crawling")
    parser.add_argument("--hidden", action="store_true", help="Scan for hidden files")
    parser.add_argument("-l", "--wordlist", help="Path to wordlist")
    parser.add_argument("--php-leak", action="store_true", help="Detect PHP leaks")
    parser.add_argument("--js-analyze", action="store_true", help="Analyze JS files")
    parser.add_argument('--xml-analyze', action='store_true', help='XML analysis')
    parser.add_argument("--xss", action="store_true", help="Scan for XSS")
    parser.add_argument("--sqli", action="store_true", help="Scan for SQLi")
    parser.add_argument("--download", action="store_true", help="Download files")
    parser.add_argument("--max-download", type=int, default=1000, help="Max files to download")
    parser.add_argument("--nuclei", action="store_true", help="Run Nuclei")
    parser.add_argument("--severity", default="critical,high,medium", help="Severity levels")
    parser.add_argument("-o", "--output", default="reports", help="Output dir")
    parser.add_argument("--format", choices=["json", "html", "csv", "all"], default="all")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════╗
║     WebStrike Pro - Security Testing Platform     ║
╚═══════════════════════════════════════════════════╝
    """)

    scope_targets = args.scope or [urlparse(args.url).hostname or args.url]
    scope_guard = ScopeGuard(scope_targets, strict_mode=True)

    print(f"[+] Target: {args.url}")
    print(f"[+] Scope: {scope_targets}")
    print(f"[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    crawler = None
    all_findings = []
    stats = {
        "discovered_urls": 0,
        "js_files": 0,
        "hidden_files": 0,
        "php_leaks": 0,
        "xss": 0,
        "sqli": 0,
        "xml": 0,
        "external_skipped": 0
    }

    async with AsyncEngine(threads=args.threads, delay=args.delay, timeout=args.timeout) as engine:

        stealth = StealthManager(aggressive=True) if args.stealth else None
        waf = WAFEvasion(technique=args.waf_evasion) if args.waf_evasion else None
        reporter = Reporter(args.output)

        # 1. Crawling
        if args.crawl or args.full or args.download or args.js_analyze or args.xml_analyze:
            print("\n[*] Phase 1: Crawling...")
            crawler = Crawler(engine, scope_guard, stealth, args.depth)
            await crawler.crawl(args.url)

            discovered_urls_list = list(crawler.discovered_urls)
            js_files_list = list(crawler.js_files)
            forms_list = crawler.forms

            print(f"[+] Discovered {len(discovered_urls_list)} URLs (before scope filter)")

            # ✅ فلترة URLs حسب Scope قبل الحفظ
            filtered_urls = [url for url in discovered_urls_list if is_in_scope(url, scope_targets)]
            external_urls = [url for url in discovered_urls_list if not is_in_scope(url, scope_targets)]
            stats["external_skipped"] = len(external_urls)

            if external_urls and args.verbose:
                print(f"[*] Filtered {len(external_urls)} external URLs")
                for url in external_urls[:5]:
                    print(f"    - Skipped: {url}")

            print(f"[+] Found {len(forms_list)} forms")
            print(f"[+] Found {len(js_files_list)} JS files")

            # ✅ حفظ كل URL داخل الـ Scope كـ finding منفصل
            for url in filtered_urls:
                finding = {
                    "type": "DISCOVERED_URL",
                    "url": url,
                    "source": "crawler",
                    "severity": "INFO",
                    "timestamp": datetime.now().isoformat()
                }
                reporter.add_finding(finding)
                all_findings.append(finding)
                stats["discovered_urls"] += 1

            # ✅ حفظ كل JS file داخل الـ Scope كـ finding منفصل
            for js_url in js_files_list:
                if not is_in_scope(js_url, scope_targets):
                    stats["external_skipped"] += 1
                    continue

                finding = {
                    "type": "JS_FILE",
                    "url": js_url,
                    "source": "crawler",
                    "severity": "INFO",
                    "timestamp": datetime.now().isoformat()
                }
                reporter.add_finding(finding)
                all_findings.append(finding)
                stats["js_files"] += 1

            # ✅ حفظ forms
            for form in forms_list:
                finding = {
                    "type": "FORM_FOUND",
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET"),
                    "inputs": form.get("inputs", []),
                    "severity": "INFO",
                    "timestamp": datetime.now().isoformat()
                }
                reporter.add_finding(finding)
                all_findings.append(finding)

        # Download
        if args.download and crawler and crawler.discovered_urls:
            print(f"\n[*] Downloading files...")
            # فلترة URLs قبل التحميل
            download_urls = [url for url in crawler.discovered_urls if is_in_scope(url, scope_targets)]
            downloaded = await download_files(
                engine, 
                download_urls, 
                args.url, 
                args.output,
                args.max_download
            )
            if downloaded:
                for item in downloaded:
                    finding = {
                        "type": "DOWNLOADED_FILE",
                        "url": item["url"],
                        "local_path": item["local_path"],
                        "size": item["size"],
                        "severity": "INFO",
                        "timestamp": datetime.now().isoformat()
                    }
                    reporter.add_finding(finding)
                    all_findings.append(finding)

        # 2. Hidden Files Scan
        if args.hidden or args.full:
            print("\n[*] Phase 2: Hidden Files Scan...")
            hidden_scanner = HiddenScanner(engine, scope_guard, waf, custom_wordlist=args.wordlist)
            hidden_results = await hidden_scanner.scan(args.url)
            print(f"[+] Found {len(hidden_results)} hidden files/directories")

            # ✅ حفظ كل hidden file كـ finding منفصل
            for item in hidden_results:
                finding = {
                    "type": "HIDDEN_FILE",
                    "url": item.get("url", ""),
                    "status": item.get("status", 0),
                    "size": item.get("size", 0),
                    "is_directory": item.get("is_directory", False),
                    "severity": item.get("severity", "MEDIUM"),
                    "timestamp": datetime.now().isoformat()
                }
                reporter.add_finding(finding)
                all_findings.append(finding)
                stats["hidden_files"] += 1

                if item.get("is_directory"):
                    print(f"  [+] Hidden DIR: {item.get('url')}/")
                else:
                    print(f"  [+] Hidden File: {item.get('url')} (Status: {item.get('status')})")

        # 3. PHP Leak Detection
        if args.php_leak or args.full:
            print("\n[*] Phase 3: PHP Source Leak Detection...")
            php_detector = PHPLeakDetector()
            php_results = await php_detector.scan_directory(engine, args.url, ["index.php", "config.php"])
            print(f"[+] Found {len(php_results)} PHP leaks")

            for item in php_results:
                finding = {
                    "type": "PHP_LEAK",
                    "url": item.get("url", ""),
                    "severity": "CRITICAL",
                    "timestamp": datetime.now().isoformat()
                }
                reporter.add_finding(finding)
                all_findings.append(finding)
                stats["php_leaks"] += 1

        # 4. JavaScript Analysis
        if args.js_analyze or args.full:
            print("\n[*] Phase 4: JavaScript Analysis...")
            if crawler and crawler.js_files:
                js_analyzer = JSAnalyzer()

                # فلترة CDN و Scope
                local_js = [url for url in crawler.js_files if is_in_scope(url, scope_targets)]
                local_js = [url for url in local_js if not any(cdn in url for cdn in ['cdnjs.cloudflare.com', 'sdk.amazonaws.com', 'cdn.jsdelivr.net'])]

                if local_js:
                    print(f"[*] Analyzing {len(local_js)} local JS files...")
                    js_results = await js_analyzer.crawl_and_analyze(engine, local_js[:20])

                    for url, analysis in js_results.items():
                        finding = {
                            "type": "JS_ANALYSIS",
                            "url": url,
                            "secrets_found": len(analysis.get("secrets", [])),
                            "secrets": analysis.get("secrets", []),
                            "endpoints": analysis.get("endpoints", []),
                            "severity": "HIGH" if analysis.get("secrets") else "INFO",
                            "timestamp": datetime.now().isoformat()
                        }
                        reporter.add_finding(finding)
                        all_findings.append(finding)

                        if analysis.get("secrets"):
                            print(f"[+] JS Secrets in {url}: {len(analysis['secrets'])} found")
                            for secret in analysis["secrets"]:
                                print(f"    - {secret.get('type', 'SECRET')}: {secret.get('value', '')[:30]}...")
                else:
                    print("[*] No local JS files to analyze (CDN/external filtered)")

        # 4b. XML Analysis
        if args.xml_analyze or args.full:
            print("\n[*] Phase 4b: XML Analysis...")
            if crawler and crawler.discovered_urls:
                xml_analyzer = XMLAnalyzer(engine)
                # فلترة XML files حسب Scope
                xml_files = [url for url in crawler.discovered_urls if url.endswith(('.xml', '.config')) and is_in_scope(url, scope_targets)]

                if xml_files:
                    xml_results = await xml_analyzer.crawl_and_analyze(xml_files[:20])

                    for url, analysis in xml_results.items():
                        finding = {
                            "type": "XML_ANALYSIS",
                            "url": url,
                            "device_type": analysis.get("device_type"),
                            "sip_accounts_count": len(analysis.get("sip_accounts", [])),
                            "sip_accounts": analysis.get("sip_accounts", []),
                            "secrets_count": len(analysis.get("secrets", [])),
                            "secrets": analysis.get("secrets", []),
                            "severity": "HIGH" if analysis.get("secrets") else "MEDIUM",
                            "timestamp": datetime.now().isoformat()
                        }
                        reporter.add_finding(finding)
                        all_findings.append(finding)
                        stats["xml"] += 1

                        if analysis.get("sip_accounts") or analysis.get("secrets"):
                            print(f"[+] XML findings in {url}")
                else:
                    print("[*] No XML files found")

        # 5. XSS Scanning
        if args.xss or args.full:
            print("\n[*] Phase 5: XSS Scanning...")
            if crawler and crawler.discovered_urls:
                xss_scanner = XSSScanner(engine, waf)
                # فلترة URLs حسب Scope
                scope_urls = [url for url in crawler.discovered_urls if is_in_scope(url, scope_targets)]

                for url in scope_urls[:10]:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params.keys():
                            result = await xss_scanner.scan_reflected(url, param)
                            if result:
                                finding = {
                                    "type": "XSS_VULNERABILITY",
                                    "url": url,
                                    "parameter": param,
                                    "severity": "HIGH",
                                    "timestamp": datetime.now().isoformat()
                                }
                                reporter.add_finding(finding)
                                all_findings.append(finding)
                                stats["xss"] += 1
                                print(f"[!] XSS: {url}?{param}")

                if stats["xss"] == 0:
                    print("[*] No XSS vulnerabilities found")

        # 6. SQLi Scanning
        if args.sqli or args.full:
            print("\n[*] Phase 6: SQL Injection Scanning...")
            if crawler and crawler.discovered_urls:
                sqli_scanner = SQLiScanner(engine, waf)
                # فلترة URLs حسب Scope
                scope_urls = [url for url in crawler.discovered_urls if is_in_scope(url, scope_targets)]

                for url in scope_urls[:10]:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params.keys():
                            results = await sqli_scanner.scan(url, param)
                            for result in results:
                                finding = {
                                    "type": "SQLI_VULNERABILITY",
                                    "url": url,
                                    "parameter": param,
                                    "subtype": result.get("subtype", "Unknown"),
                                    "severity": "CRITICAL",
                                    "timestamp": datetime.now().isoformat()
                                }
                                reporter.add_finding(finding)
                                all_findings.append(finding)
                                stats["sqli"] += 1
                                print(f"[!] SQLi: {url}?{param}")

                if stats["sqli"] == 0:
                    print("[*] No SQLi vulnerabilities found")

        # Generate Reports
        print("\n" + "="*60)
        print("GENERATING REPORTS")
        print("="*60)

        if args.format in ["json", "all"]:
            path = reporter.generate_json()
            print(f"[+] JSON: {path}")
        if args.format in ["html", "all"]:
            path = reporter.generate_html()
            print(f"[+] HTML: {path}")
        if args.format in ["csv", "all"]:
            path = reporter.generate_csv()
            print(f"[+] CSV: {path}")

        # ✅ طباعة الملخص النهائي
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"[+] Total findings: {len(all_findings)}")
        print(f"  - {stats['discovered_urls']} DISCOVERED_URL")
        print(f"  - {stats['js_files']} JS_FILE")
        print(f"  - {stats['hidden_files']} HIDDEN_FILE")
        if stats['external_skipped'] > 0:
            print(f"  - {stats['external_skipped']} EXTERNAL_URLS_SKIPPED")
        if stats['php_leaks'] > 0:
            print(f"  - {stats['php_leaks']} PHP_LEAK")
        if stats['xml'] > 0:
            print(f"  - {stats['xml']} XML_ANALYSIS")
        if stats['xss'] > 0:
            print(f"  - {stats['xss']} XSS_VULNERABILITY")
        if stats['sqli'] > 0:
            print(f"  - {stats['sqli']} SQLI_VULNERABILITY")
        print("="*60)
        print(f"[+] Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
