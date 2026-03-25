"""
Reporter - Multi-format Report Generation
"""
import json
import csv
import html
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

class Reporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.findings: List[Dict] = []
        
    def add_finding(self, finding: Dict):
        self.findings.append(finding)
        
    def generate_json(self, filename: str = None) -> str:
        filename = filename or f"report_{self.timestamp}.json"
        filepath = self.output_dir / filename
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings)
            },
            "findings": self.findings
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def generate_html(self, filename: str = None) -> str:
        filename = filename or f"report_{self.timestamp}.html"
        filepath = self.output_dir / filename
        
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14", 
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
            "INFO": "#6c757d"
        }
        
        html_content = f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>WebStrike Pro Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: #343a40; color: white; padding: 20px; border-radius: 5px; }}
                .finding {{ background: white; margin: 10px 0; padding: 15px; border-radius: 5px; 
                           box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-right: 5px solid #ddd; }}
                .CRITICAL {{ border-right-color: {severity_colors["CRITICAL"]}; }}
                .HIGH {{ border-right-color: {severity_colors["HIGH"]}; }}
                .MEDIUM {{ border-right-color: {severity_colors["MEDIUM"]}; }}
                .LOW {{ border-right-color: {severity_colors["LOW"]}; }}
                .badge {{ padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
                pre {{ background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ WebStrike Pro - Security Report</h1>
                <p>Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p>Total Findings: {len(self.findings)}</p>
            </div>
        """
        
        for finding in self.findings:
            severity = finding.get("severity", "INFO")
            color = severity_colors.get(severity, "#6c757d")
            
            html_content += f"""
            <div class="finding {severity}">
                <h3>{html.escape(finding.get("type", "Unknown"))}</h3>
                <span class="badge" style="background: {color}">{severity}</span>
                <p><strong>URL:</strong> {html.escape(finding.get("url", ""))}</p>
                <p><strong>Parameter:</strong> {html.escape(finding.get("parameter", "N/A"))}</p>
                {f'<pre>{html.escape(finding.get("payload", ""))}</pre>' if finding.get("payload") else ""}
                {f'<p><strong>Evidence:</strong> {html.escape(finding.get("evidence", ""))}</p>' if finding.get("evidence") else ""}
            </div>
            """
        
        html_content += "</body></html>"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def generate_csv(self, filename: str = None) -> str:
        filename = filename or f"report_{self.timestamp}.csv"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Severity", "URL", "Parameter", "Payload"])
            
            for finding in self.findings:
                writer.writerow([
                    finding.get("type", ""),
                    finding.get("severity", ""),
                    finding.get("url", ""),
                    finding.get("parameter", ""),
                    finding.get("payload", "")
                ])
        
        return str(filepath)