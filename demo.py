#!/usr/bin/env python3
"""
Demo script to test Mini-SIEM functionality
"""

from mini_siem import MiniSIEM
import json

def run_demo():
    print("🛡️ Mini-SIEM Demo")
    print("=" * 50)
    
    # Initialize SIEM
    siem = MiniSIEM()
    
    # Load and analyze sample logs
    try:
        with open('auth.log', 'r') as f:
            auth_content = f.read()
        siem.parse_auth_log(auth_content)
        print("✅ Analyzed auth.log")
    except FileNotFoundError:
        print("❌ auth.log not found")
    
    try:
        with open('access.log', 'r') as f:
            web_content = f.read()
        siem.parse_web_log(web_content)
        print("✅ Analyzed access.log")
    except FileNotFoundError:
        print("❌ access.log not found")
    
    # Generate report
    report = siem.generate_threat_report()
    print("\n" + report)
    
    # Export results
    filename = siem.export_results("demo_report.json")
    print(f"\n📄 Report exported to: {filename}")

if __name__ == "__main__":
    run_demo()
