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

                safe_path = '/'.join(safe_parts)
                if not safe_path:
                    safe_path = "index.html"

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
                print(f"  [+] Downloaded: {url} -> {local_path}")

        except Exception as e:
            if "-v" in sys.argv or "--verbose" in sys.argv:
                print(f"  [!] Failed to download {url}: {e}")

    print(f"\n[+] Total downloaded: {downloaded_count} files to {download_dir}")
    return downloaded_count


def is_in_scope(url: str, scope_targets: list) -> bool:
    """Check if URL is within scope (not external CDN)"""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    for scope in scope_targets:
        scope_host = scope.replace("*.", "")
        if scope_host in hostname or hostname in scope_host:
            return True
    return False


async def main():
    parser = argparse.ArgumentParser(
        description="WebStrike Pro - Advanced Web Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u https://example.com --full
  python main.py -u https://example.com --full --download
  python main.py -u https://example.com --crawl --hidden
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

    crawler = None

    async with AsyncEngine(threads=args.threads, delay=args.delay, timeout=args.timeout) as engine:

        stealth = StealthManager(aggressive=True) if args.stealth else None
        waf = WAFEvasion(technique=args.waf_evasion) if args.waf_evasion else None
        reporter = Reporter(args.output)

        # 1. Crawling
        if args.crawl or args.full or args.download or args.js_analyze or args.xml_analyze:
            print("\n[*] Phase 1: Crawling...")
            crawler = Crawler(engine, scope_guard, stealth, args.depth)
            await crawler.crawl(args.url)
            print(f"[+] Discovered {len(crawler.discovered_urls)} URLs")
            print(f"[+] Found {len(crawler.forms)} forms")
            print(f"[+] Found {len(crawler.js_files)} JS files")

            # ✅ إضافة نتائج Crawler للتقرير
            reporter.add_finding({
                "type": "CRAWLER_SUMMARY",
                "target": args.url,
                "discovered_urls_count": len(crawler.discovered_urls),
                "forms_count": len(crawler.forms),
                "js_files_count": len(crawler.js_files),
                "urls": list(crawler.discovered_urls)[:50],
                "severity": "INFO"
            })

        # Download
        if args.download and crawler and crawler.discovered_urls:
            print(f"\n[*] Downloading files...")
            await download_files(engine, list(crawler.discovered_urls), args.url, args.output, args.max_download)

        # 2. Hidden Files Scan
        if args.hidden or args.full:
            print("\n[*] Phase 2: Hidden Files Scan...")
            hidden_scanner = HiddenScanner(engine, scope_guard, waf, custom_wordlist=args.wordlist)
            hidden_results = await hidden_scanner.scan(args.url)
            print(f"[+] Found {len(hidden_results)} hidden files")

            # ✅ إضافة جميع نتائج Hidden Scanner للتقرير
            for finding in hidden_results:  # كل النتائج وليس فقط Critical
                reporter.add_finding({
                    "type": "HIDDEN_FILE",
                    "url": finding.get("url", ""),
                    "status": finding.get("status", 0),
                    "size": finding.get("size", 0),
                    "severity": finding.get("severity", "MEDIUM")
                })

        # 3. PHP Leak
        if args.php_leak or args.full:
            print("\n[*] Phase 3: PHP Source Leak Detection...")
            php_detector = PHPLeakDetector()
            php_results = await php_detector.scan_directory(engine, args.url, ["index.php", "config.php"])
            print(f"[+] Found {len(php_results)} PHP leaks")
            for finding in php_results:
                reporter.add_finding(finding)

        # 4. JavaScript Analysis
        if args.js_analyze or args.full:
            print("\n[*] Phase 4: JavaScript Analysis...")
            if crawler and crawler.js_files:
                js_analyzer = JSAnalyzer()
                js_results = await js_analyzer.crawl_and_analyze(engine, list(crawler.js_files)[:20])

                for url, analysis in js_results.items():
                    # ✅ فحص الـ Scope - تجاهل CDN الخارجية
                    if not is_in_scope(url, scope_targets):
                        if args.verbose:
                            print(f"  [*] Skipping external JS: {url}")
                        continue

                    if analysis.get("secrets"):
                        print(f"[+] Found secrets in {url}")
                        reporter.add_finding({
                            "type": "JS_SECRET",
                            "url": url,
                            "secrets": analysis["secrets"],
                            "severity": "HIGH"
                        })

        # 4b. XML Analysis
        if args.xml_analyze or args.full:
            print("\n[*] Phase 4b: XML Analysis...")
            if crawler and crawler.discovered_urls:
                xml_analyzer = XMLAnalyzer(engine)
                xml_files = [url for url in crawler.discovered_urls if url.endswith(('.xml', '.config'))]

                if xml_files:
                    xml_results = await xml_analyzer.crawl_and_analyze(xml_files[:20])

                    for url, analysis in xml_results.items():
                        if analysis.get("sip_accounts") or analysis.get("secrets"):
                            print(f"[+] XML findings in {url}")

                            # ✅ إضافة نتائج XML للتقرير
                            reporter.add_finding({
                                "type": "XML_CONFIG",
                                "url": url,
                                "device_type": analysis.get("device_type"),
                                "sip_accounts": analysis.get("sip_accounts", []),
                                "secrets": analysis.get("secrets", []),
                                "severity": "HIGH" if analysis.get("secrets") else "MEDIUM"
                            })
                else:
                    print("[*] No XML files found")

        # 5. XSS Scanning
        if args.xss or args.full:
            print("\n[*] Phase 5: XSS Scanning...")
            if crawler and crawler.discovered_urls:
                xss_scanner = XSSScanner(engine, waf)
                for url in list(crawler.discovered_urls)[:10]:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params.keys():
                            result = await xss_scanner.scan_reflected(url, param)
                            if result:
                                reporter.add_finding(result)
                                print(f"[!] XSS found: {url}")

        # 6. SQLi Scanning
        if args.sqli or args.full:
            print("\n[*] Phase 6: SQL Injection Scanning...")
            if crawler and crawler.discovered_urls:
                sqli_scanner = SQLiScanner(engine, waf)
                for url in list(crawler.discovered_urls)[:10]:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params.keys():
                            results = await sqli_scanner.scan(url, param)
                            for finding in results:
                                reporter.add_finding(finding)
                                print(f"[!] SQLi found: {url}")

        # Generate Reports
        print("\n[*] Generating reports...")
        if args.format in ["json", "all"]:
            path = reporter.generate_json()
            print(f"[+] JSON: {path}")
        if args.format in ["html", "all"]:
            path = reporter.generate_html()
            print(f"[+] HTML: {path}")
        if args.format in ["csv", "all"]:
            path = reporter.generate_csv()
            print(f"[+] CSV: {path}")

        print(f"\n[+] Scan completed! Total findings: {len(reporter.findings)}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
