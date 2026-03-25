"""
Nuclei Integration - Automated Vulnerability Scanning
"""
import subprocess
import json
import asyncio
import tempfile
import os
from typing import List, Dict, Optional

class NucleiIntegration:
    def __init__(self, templates_path: Optional[str] = None, 
                 severity: List[str] = None,
                 rate_limit: int = 150):
        self.templates_path = templates_path or os.path.expanduser("~/nuclei-templates")
        self.severity = severity or ["critical", "high", "medium"]
        self.rate_limit = rate_limit
        self.output_file = None
        
    async def scan_target(self, target: str, output_format: str = "json") -> List[Dict]:
        """Scan target using Nuclei"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            self.output_file = f.name
        
        cmd = [
            "nuclei",
            "-u", target,
            "-json",
            "-o", self.output_file,
            "-rate-limit", str(self.rate_limit),
            "-severity", ",".join(self.severity),
            "-silent"
        ]
        
        if self.templates_path and os.path.exists(self.templates_path):
            cmd.extend(["-t", self.templates_path])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode not in [0, 1]:  # 1 means vulnerabilities found
                print(f"[Nuclei] Warning: Exit code {process.returncode}")
            
            return await self._parse_results()
            
        except FileNotFoundError:
            print("[Nuclei] Error: nuclei not found in PATH")
            return []
        except Exception as e:
            print(f"[Nuclei] Error: {e}")
            return []
    
    async def scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan list of URLs"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for url in urls:
                f.write(url + "\n")
            urls_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name
        
        cmd = [
            "nuclei",
            "-l", urls_file,
            "-json",
            "-o", output_file,
            "-rate-limit", str(self.rate_limit),
            "-severity", ",".join(self.severity),
            "-silent"
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(*cmd)
            await process.wait()
            
            results = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            results.append(json.loads(line))
                        except:
                            pass
            
            os.unlink(urls_file)
            os.unlink(output_file)
            return results
            
        except Exception as e:
            print(f"[Nuclei] Error: {e}")
            return []
    
    async def _parse_results(self) -> List[Dict]:
        """Parse Nuclei results"""
        results = []
        
        if not self.output_file or not os.path.exists(self.output_file):
            return results
        
        try:
            with open(self.output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        results.append({
                            "template": finding.get("template-id", ""),
                            "name": finding.get("info", {}).get("name", ""),
                            "severity": finding.get("info", {}).get("severity", ""),
                            "host": finding.get("host", ""),
                            "matched": finding.get("matched-at", ""),
                            "description": finding.get("info", {}).get("description", ""),
                        })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[Nuclei] Parse error: {e}")
        finally:
            if os.path.exists(self.output_file):
                os.unlink(self.output_file)
        
        return results
    
    def is_available(self) -> bool:
        """Check if Nuclei is available"""
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
            return True
        except:
            return False