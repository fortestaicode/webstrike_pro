"""
FFUF Bridge - FFUF-level Performance Integration
"""
import subprocess
import json
import asyncio
import tempfile
import os
from typing import List, Dict, Optional

class FFUFBridge:
    def __init__(self, wordlist: str, threads: int = 40, 
                 extensions: str = None,
                 filter_status: List[int] = None):
        self.wordlist = wordlist
        self.threads = threads
        self.extensions = extensions
        self.filter_status = filter_status or [404]
        
    async def fuzz_directory(self, target: str, wordlist: Optional[str] = None) -> List[Dict]:
        """Directory fuzzing using FFUF"""
        if not self._check_ffuf():
            print("[FFUF] ffuf not found, using internal engine")
            return []
        
        wordlist = wordlist or self.wordlist
        if not wordlist or not os.path.exists(wordlist):
            print(f"[FFUF] Wordlist not found: {wordlist}")
            return []
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name
        
        cmd = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-t", str(self.threads),
            "-o", output_file,
            "-of", "json",
            "-ac",  # Auto-calibration
            "-s"    # Silent
        ]
        
        if self.extensions:
            cmd.extend(["-e", self.extensions])
        
        for status in self.filter_status:
            cmd.extend(["-fc", str(status)])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            return self._parse_ffuf_output(output_file)
            
        except Exception as e:
            print(f"[FFUF] Error: {e}")
            return []
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    async def fuzz_parameters(self, target: str, param_wordlist: str, 
                             value_wordlist: str) -> List[Dict]:
        """Parameter fuzzing (POST/GET)"""
        if not self._check_ffuf():
            return []
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name
        
        # Mode: clusterbomb for parameters
        cmd = [
            "ffuf",
            "-u", target,
            "-w", f"{param_wordlist}:PARAM",
            "-w", f"{value_wordlist}:VALUE",
            "-X", "GET",
            "-d", "PARAM=VALUE",
            "-t", str(self.threads),
            "-o", output_file,
            "-of", "json",
            "-mode", "clusterbomb"
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(*cmd)
            await process.wait()
            return self._parse_ffuf_output(output_file)
        except Exception as e:
            print(f"[FFUF] Error: {e}")
            return []
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_ffuf_output(self, output_file: str) -> List[Dict]:
        """Parse FFUF output"""
        results = []
        
        if not os.path.exists(output_file):
            return results
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
                for result in data.get("results", []):
                    results.append({
                        "url": result.get("url", ""),
                        "status": result.get("status", 0),
                        "length": result.get("length", 0),
                        "words": result.get("words", 0),
                        "lines": result.get("lines", 0),
                        "duration": result.get("duration", 0),
                    })
        except Exception as e:
            print(f"[FFUF] Parse error: {e}")
        
        return results
    
    def _check_ffuf(self) -> bool:
        """Check if FFUF is available"""
        try:
            subprocess.run(["ffuf", "-V"], capture_output=True, check=True)
            return True
        except:
            return False