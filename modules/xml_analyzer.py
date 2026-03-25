"""
XML Analyzer - Advanced XML Analysis with Fuzzy Matching
تحليل ملفات XML مع دعم تطابق مرن للكلمات المفتاحية
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

class XMLAnalyzer:
    def __init__(self, engine):
        self.engine = engine
        # تعريف الكلمات المفتاحية المرنة (تطابق جزئي)
        self.keyword_mappings = {
            "server": [
                'server', 'host', 'url', 'ip', 'domain', 'proxy', 
                'outbound_proxy', 'registrar', 'server_address', 
                'srv_addr', 'host_name', 'network_address'
            ],
            "username": [
                'user', 'username', 'name', 'auth_name', 'display_name',
                'number', 'extension', 'account', 'line', 'user_name',
                'uname', 'userid', 'authuser', 'sip_user'
            ],
            "password": [
                'pass', 'password', 'secret', 'auth_pass', 'passwd', 
                'pwd', 'sip_pass', 'credential', 'auth_secret',
                'passphrase', 'key', 'pin', 'code'
            ],
            "port": [
                'port', 'sip_port', 'server_port', 'proxy_port', 'local_port'
            ]
        }
        
        # أنماط خاصة بأجهزة Fanvil و SIP بشكل عام
        self.device_patterns = {
            "fanvil": r'<fanvil_config',
            "yealink": r'<YealinkIPPhoneConfig',
            "cisco": r'<flat-profile',
            "grandstream": r'<gs_provision',
            "polycom": r'<polycomConfig',
        }
    
    def analyze(self, xml_content: str, base_url: str = "") -> Dict:
        """
        تحليل شامل لمحتوى XML
        """
        results = {
            "device_type": None,
            "endpoints": [],
            "sip_accounts": [],  # حسابات SIP المكتشفة
            "secrets": [],
            "databases": [],
            "network_config": [],
            "raw_credentials": []
        }
        
        # 1. اكتشاف نوع الجهاز/الملف
        results["device_type"] = self._detect_device_type(xml_content)
        
        # 2. تحليل بنية XML العودي
        try:
            root = ET.fromstring(xml_content)
            self._parse_element_recursive(root, results, parent_tag="")
        except ET.ParseError as e:
            # إذا كان XML غير صالح، استخدم Regex فقط
            results["parse_error"] = str(e)
            self._fallback_regex_analysis(xml_content, results)
        
        # 3. تحليل خاص بأجهزة Fanvil
        if results["device_type"] == "fanvil":
            self._extract_fanvil_specific(xml_content, results)
        
        # 4. استخراج endpoints عامة
        self._extract_generic_endpoints(xml_content, base_url, results)
        
        return results
    
    def _detect_device_type(self, xml_content: str) -> Optional[str]:
        """اكتشاف نوع الجهاز من الـ XML"""
        xml_lower = xml_content.lower()
        
        for device, pattern in self.device_patterns.items():
            if re.search(pattern, xml_content, re.IGNORECASE):
                return device
        
        # اكتشاف عام لملفات SIP
        if any(keyword in xml_lower for keyword in ['<sip', '<account', '<line']):
            return "generic_sip"
        
        return "unknown"
    
    def _parse_element_recursive(self, element, results: Dict, parent_tag: str = ""):
        """
        تحليل عنصر XML بشكل عودي مع مراعاة السياق الأب
        """
        tag = element.tag.split('}')[-1] if '}' in element.tag else element.tag
        tag_lower = tag.lower()
        text = element.text.strip() if element.text else ""
        
        # تجاهل العناصر الفارغة
        if not text:
            # متابعة العناصر الفرعية فقط
            for child in element:
                self._parse_element_recursive(child, results, parent_tag=tag)
            return
        
        # --- اكتشاف السيرفر (Server/Host/IP) ---
        if self._tag_matches_any(tag_lower, self.keyword_mappings["server"]):
            server_info = {
                "type": "server",
                "tag": tag,
                "value": text,
                "parent": parent_tag,
                "context": self._get_context_from_parent(parent_tag)
            }
            results["endpoints"].append(text)
            results["network_config"].append(server_info)
        
        # --- اكتشاف اسم المستخدم (Username) ---
        elif self._tag_matches_any(tag_lower, self.keyword_mappings["username"]):
            user_info = {
                "type": "username",
                "tag": tag,
                "value": text,
                "parent": parent_tag
            }
            results["raw_credentials"].append(user_info)
            # إضافة إلى حساب SIP إذا كان الأب هو LineX
            self._add_to_sip_account(results, parent_tag, "username", text)
        
        # --- اكتشاف كلمة المرور (Password) ---
        elif self._tag_matches_any(tag_lower, self.keyword_mappings["password"]):
            pass_info = {
                "type": "password",
                "tag": tag,
                "value": text[:20] + "..." if len(text) > 20 else text,  # إخفاء جزئي للأمان
                "full_length": len(text),
                "parent": parent_tag,
                "severity": "CRITICAL"
            }
            results["secrets"].append(pass_info)
            results["raw_credentials"].append(pass_info)
            # إضافة إلى حساب SIP
            self._add_to_sip_account(results, parent_tag, "password", text)
        
        # --- اكتشاف المنفذ (Port) ---
        elif self._tag_matches_any(tag_lower, self.keyword_mappings["port"]):
            port_info = {
                "type": "port",
                "tag": tag,
                "value": text,
                "parent": parent_tag
            }
            results["network_config"].append(port_info)
            self._add_to_sip_account(results, parent_tag, "port", text)
        
        # متابعة العناصر الفرعية
        for child in element:
            self._parse_element_recursive(child, results, parent_tag=tag)
    
    def _tag_matches_any(self, tag: str, keywords: List[str]) -> bool:
        """
        التحقق إذا كان الـ tag يطابق أي من الكلمات المفتاحية
        يدعم: تطابق تام، يحتوي على، يبدأ بـ، ينتهي بـ
        """
        tag_clean = tag.replace('_', '').replace('-', '').lower()
        
        for keyword in keywords:
            keyword_clean = keyword.replace('_', '').replace('-', '').lower()
            
            # تطابق تام
            if tag_clean == keyword_clean:
                return True
            # يحتوي على الكلمة
            if keyword_clean in tag_clean:
                return True
            # الكلمة تحتوي على الـ tag
            if tag_clean in keyword_clean and len(tag_clean) > 3:
                return True
        
        return False
    
    def _get_context_from_parent(self, parent_tag: str) -> str:
        """تحديد السياق من اسم العنصر الأب"""
        parent_lower = parent_tag.lower()
        
        if 'line' in parent_lower:
            return f"sip_line:{parent_tag}"
        elif 'account' in parent_lower:
            return f"account:{parent_tag}"
        elif 'server' in parent_lower or 'proxy' in parent_lower:
            return "server_config"
        elif 'global' in parent_lower:
            return "global_settings"
        
        return "general"
    
    def _add_to_sip_account(self, results: Dict, parent_tag: str, 
                           field_type: str, value: str):
        """
        إضافة البيانات إلى هيكل حساب SIP منظم
        """
        # البحث عن حساب موجود بنفس اسم الأب
        existing_account = None
        for account in results["sip_accounts"]:
            if account.get("line_name") == parent_tag:
                existing_account = account
                break
        
        # إنشاء حساب جديد إذا لم ي exist
        if not existing_account:
            existing_account = {
                "line_name": parent_tag,
                "server": None,
                "username": None,
                "password": None,
                "port": "5060"  # افتراضي
            }
            results["sip_accounts"].append(existing_account)
        
        # إضافة الحقل
        if field_type in existing_account:
            existing_account[field_type] = value
    
    def _extract_fanvil_specific(self, xml_content: str, results: Dict):
        """استخراج إعدادات خاصة بأجهزة Fanvil"""
        # أنماط خاصة بـ Fanvil
        patterns = {
            "firmware": r'<Firmware>([^<]+)',
            "mac_address": r'<MAC>([^<]+)',
            "model": r'<Model>([^<]+)',
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, xml_content, re.IGNORECASE)
            if matches:
                results[key] = matches[0]
    
    def _extract_generic_endpoints(self, xml_content: str, base_url: str, results: Dict):
        """استخراج endpoints عامة"""
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, xml_content)
        
        for url in urls:
            if url not in results["endpoints"]:
                results["endpoints"].append(url)
    
    def _fallback_regex_analysis(self, xml_content: str, results: Dict):
        """تحليل احتياطي باستخدام Regex إذا فشل ElementTree"""
        # استخراج جميع الـ tags والقيم
        tag_value_pattern = r'<([a-zA-Z0-9_\-]+)[^>]*>([^<]+)</\1>'
        matches = re.findall(tag_value_pattern, xml_content)
        
        for tag, value in matches:
            tag_lower = tag.lower()
            
            # التحقق من نوع البيانات
            if self._tag_matches_any(tag_lower, self.keyword_mappings["password"]):
                results["secrets"].append({
                    "type": "password",
                    "tag": tag,
                    "value": value[:20] + "...",
                    "method": "regex_fallback"
                })
            elif self._tag_matches_any(tag_lower, self.keyword_mappings["server"]):
                results["endpoints"].append(value)
    
    async def crawl_and_analyze(self, urls: List[str]) -> Dict[str, Dict]:
        """تحميل وتحليل ملفات XML من URLs"""
        results = {}
        
        xml_extensions = ('.xml', '.config', '.cfg', '.provision', 
                         '.sip', '.phone', '.device', '.y000', '.t000')
        
        for url in urls:
            if not url.lower().endswith(xml_extensions):
                continue
            
            try:
                res = await self.engine.request("GET", url)
                if res.status == 200 and res.body:
                    analysis = self.analyze(res.body, url)
                    results[url] = analysis
                    
                    # طباعة ملخص سريع
                    if analysis["sip_accounts"]:
                        print(f"  [+] Found {len(analysis['sip_accounts'])} SIP accounts in {url}")
            except Exception as e:
                print(f"  [!] Error analyzing {url}: {e}")
        
        return results
    
    def generate_sip_report(self, results: Dict) -> str:
        """توليد تقرير منسق لحسابات SIP"""
        lines = ["\n=== SIP Accounts Discovered ==="]
        
        for i, account in enumerate(results.get("sip_accounts", []), 1):
            if account.get("username") or account.get("password"):
                lines.append(f"\nAccount #{i} ({account.get('line_name', 'Unknown')}):")
                lines.append(f"  Server: {account.get('server', 'N/A')}")
                lines.append(f"  Username: {account.get('username', 'N/A')}")
                lines.append(f"  Password: {'*' * min(len(str(account.get('password', ''))), 8)}")
                lines.append(f"  Port: {account.get('port', '5060')}")
        
        return "\n".join(lines)


# ====== اختبار مباشر ======
if __name__ == "__main__":
    # مثال المستخدم
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<fanvil_config>
    <Global_Settings>
        <language>English</language>
    </Global_Settings>
    <SIP_Settings>
        <Line1>
            <Server_Address>192.168.1.100</Server_Address>
            <User_Name>2001</User_Name>
            <Password>123456</Password>
        </Line1>
        <Line2>
            <Server>192.168.1.101</Server>
            <Auth_Name>2002</Auth_Name>
            <Secret>abcdef</Secret>
        </Line2>
    </SIP_Settings>
</fanvil_config>"""
    
    analyzer = XMLAnalyzer(None)
    result = analyzer.analyze(sample_xml)
    
    print("Device Type:", result["device_type"])
    print("\nSIP Accounts Found:", len(result["sip_accounts"]))
    print(analyzer.generate_sip_report(result))