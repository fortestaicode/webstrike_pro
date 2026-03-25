
"""
JS Analyzer - Complete Version
All features: Endpoints, Secrets, URLs, Parameters, Crypto, VoIP
"""
import re
import urllib.parse
from typing import Set, List, Dict, Optional

class JSAnalyzer:
    def __init__(self):
        self.patterns = {
            "endpoints": [
                r"[\"\']((?:\/|https?:\/\/)[a-zA-Z0-9_\-\/\.]+\/(?:api|v\d|graphql|rest|service|endpoint)[a-zA-Z0-9_\-\/\.]*)[\"\']",
                r"[\"\'](\/api\/[a-zA-Z0-9_\-\/\?&=]+)[\"\']",
                r"(https?:\/\/[^\s\"\']+)",
            ],

            "secrets": {
                # Cloud Providers
                "aws_key": r"AKIA[0-9A-Z]{16}",
                "aws_secret": r"[\"\'][0-9a-zA-Z\/\+]{40}[\"\']",

                # Crypto & Blockchain
                "bitcoin_private_key": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}",
                "ethereum_private_key": r"0x[a-fA-F0-9]{64}",
                "crypto_mnemonic": r"\b(?:abandon|ability|able|about)\b(?:\s+\b(?:abandon|ability|able|about|above)\b){11,23}",
                "coinbase_api": r"coinbase[a-zA-Z0-9_\-]{10,50}",
                "binance_api": r"binance[a-zA-Z0-9_\-]{10,50}",
                "etherscan_api": r"etherscan[a-zA-Z0-9_\-]{10,50}",

                # VoIP & Communications
                "twilio_sid": r"AC[a-f0-9]{32}",
                "twilio_token": r"[\"\'][a-f0-9]{32}[\"\']",
                "vonage_key": r"vonage[a-zA-Z0-9_\-]{10,}",
                "plivo_auth": r"plivo[a-zA-Z0-9_\-]{10,}",
                "sendgrid_key": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
                "mailgun_key": r"key-[a-f0-9]{32}",

                # Generic
                "api_key": r"(?:api[_-]?key|apikey)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{16,})[\"\']",
                "secret": r"(?:secret|password|passwd|pwd)\s*[:=]\s*[\"\']([^\"\']{8,})[\"\']",
                "token": r"(?:token|bearer)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-\.]{20,})[\"\']",
                "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
                "private_key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
                "github_token": r"gh[pousr]_[A-Za-z0-9_]{36}",
            },

            "urls": [
                r"https?:\/\/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s\"\']*)?",
            ],

            "parameters": [
                r"\?(?:[a-zA-Z0-9_]+=[^&]*&?)+",
            ]
        }

        self.interesting_patterns = [
            (r"debug\s*[=:]\s*true", "Debug mode enabled"),
            (r"localhost|127\.0\.0\.1|0\.0\.0\.0", "Localhost reference"),
            (r"admin|dashboard|panel", "Admin panel reference"),
            (r"internal|private|restricted", "Internal endpoint"),
        ]

    def analyze(self, js_content: str, base_url: str) -> Dict:
        """Analyze JavaScript content comprehensively"""
        results = {
            "endpoints": set(),
            "secrets": [],
            "urls": set(),
            "crypto_assets": [],
            "voip_services": [],
            "interesting": []
        }

        # 1. Extract endpoints
        for pattern in self.patterns["endpoints"]:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                full_url = urllib.parse.urljoin(base_url, match)
                results["endpoints"].add(full_url)

        # 2. Extract secrets with categorization
        for secret_type, pattern in self.patterns["secrets"].items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                secret_data = {
                    "type": secret_type,
                    "value": match[:50] + "..." if len(match) > 50 else match,
                    "context": self._get_context(js_content, match)
                }

                # Categorize
                if any(x in secret_type for x in ["bitcoin", "ethereum", "crypto", "coinbase", "binance", "etherscan"]):
                    secret_data["category"] = "CRYPTO"
                    results["crypto_assets"].append(secret_data)
                elif any(x in secret_type for x in ["twilio", "vonage", "plivo", "sendgrid", "mailgun"]):
                    secret_data["category"] = "VOIP/COMM"
                    results["voip_services"].append(secret_data)

                results["secrets"].append(secret_data)

        # 3. Extract URLs
        for pattern in self.patterns["urls"]:
            matches = re.findall(pattern, js_content)
            results["urls"].update(matches)

        # 4. Extract interesting patterns
        for pattern, desc in self.interesting_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                results["interesting"].append(desc)

        return {
            "endpoints": list(results["endpoints"]),
            "secrets": results["secrets"],
            "urls": list(results["urls"]),
            "crypto_assets": results["crypto_assets"],
            "voip_services": results["voip_services"],
            "interesting": results["interesting"]
        }

    def _get_context(self, content: str, match: str, window: int = 50) -> str:
        pos = content.find(match)
        if pos == -1:
            return ""
        start = max(0, pos - window)
        end = min(len(content), pos + len(match) + window)
        return content[start:end].replace("\n", " ")

    async def crawl_and_analyze(self, engine, urls: List[str]) -> Dict[str, Dict]:
        results = {}
        for url in urls:
            if not url.endswith(".js"):
                continue
            res = await engine.request("GET", url)
            if res.status == 200 and res.body:
                results[url] = self.analyze(res.body, url)
        return results
