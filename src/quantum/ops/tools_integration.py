#!/usr/bin/env python3
"""
Security tool integration for Metasploit, Shodan, sn1per, wifite 3, Nmap, etc.
Provides a unified interface for invoking these tools.
"""

import subprocess
import shutil
from typing import Dict, List

class SecurityToolIntegration:
    """Integrate with external security tools."""
    
    TOOLS = {
        "metasploit": {
            "command": "msfconsole",
            "args": ["-q", "-x"],
            "description": "Metasploit Framework - exploitation and post-exploitation"
        },
        "shodan": {
            "command": "shodan",
            "args": [],
            "description": "Shodan - internet-wide device search"
        },
        "sn1per": {
            "command": "sn1per",
            "args": [],
            "description": "Sn1per - web application vulnerability scanner"
        },
        "wifite3": {
            "command": "wifite3",
            "args": ["--wps", "--wpa"],
            "description": "Wifite 3 - automated Wi-Fi password cracking"
        },
        "nmap": {
            "command": "nmap",
            "args": ["-sV", "-p-"],
            "description": "Nmap - network discovery and port scanning"
        },
        "burpsuite": {
            "command": "burpsuite",
            "args": [],
            "description": "Burp Suite - web application security testing"
        },
        "aircrack": {
            "command": "aircrack-ng",
            "args": ["-w", "rockyou.txt"],
            "description": "Aircrack-ng - WEP/WPA cracking"
        },
        "john": {
            "command": "john",
            "args": [],
            "description": "John the Ripper - password cracking"
        },
        "hashcat": {
            "command": "hashcat",
            "args": ["-m", "0"],
            "description": "Hashcat - GPU-accelerated password cracking"
        }
    }
    
    def __init__(self):
        self.active_tools = []
    
    def invoke(self, tool: str, args: List[str] = None) -> Dict:
        """Invoke a security tool with given arguments."""
        if tool not in self.TOOLS:
            return {"ok": False, "error": f"Unknown tool: {tool}"}
        
        config = self.TOOLS[tool]
        cmd = [config["command"]] + config["args"] + (args or [])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            return {
                "ok": True,
                "tool": tool,
                "command": " ".join(cmd),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    def list_tools(self) -> List[str]:
        """List available security tools."""
        return list(self.TOOLS.keys())
    
    def check_available(self, tool: str) -> bool:
        """Check if a security tool is available."""
        if tool not in self.TOOLS:
            return False
        return shutil.which(tool) is not None
    
    def get_tool_info(self, tool: str) -> Dict:
        """Get information about a security tool."""
        if tool not in self.TOOLS:
            return {"ok": False, "error": f"Unknown tool: {tool}"}
        return {"ok": True, **self.TOOLS[tool]}


def main():
    """Example usage."""
    integration = SecurityToolIntegration()
    print("Available tools:", integration.list_tools())
    
    # Check which tools are installed
    for tool in integration.list_tools():
        available = integration.check_available(tool)
        print(f"  {tool}: {'✓' if available else '✗'}")

if __name__ == "__main__":
    main()