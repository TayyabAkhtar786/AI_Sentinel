#!/usr/bin/env python3
"""
AI-Sentinel Main Orchestrator
Runs the complete assessment pipeline from CLI
"""

import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import NetworkScanner
from ai_analyzer import AIThreatAnalyzer
from attack_engine import AttackSimulator
from report_generator import ReportGenerator


def run_assessment(target='127.0.0.1'):

    print("=" * 60)
    print("🛡️  AI-SENTINEL v2.0")
    print("    AI-Powered Security Assessment")
    print("=" * 60)
    print(f"    Target: {target}")
    print(f"    Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Step 1: Initialize
    print("\n📦 Step 1: Initializing...")
    scanner = NetworkScanner()
    ai = AIThreatAnalyzer()
    reporter = ReportGenerator()

    if not ai.load_model():
        ai.train()

    # Step 2: Scan
    print("\n" + "=" * 60)
    print("🔍 Step 2: Network Scanning")
    print("=" * 60)
    scan_results = scanner.adaptive_scan(target)
    summary = scanner.get_summary(scan_results)

    print(f"\n📊 Scan Summary:")
    print(f"   Hosts:    {summary['total_hosts']}")
    print(f"   Ports:    {summary['total_ports']}")
    print(f"   Services: {summary['services']}")

    if summary['total_ports'] == 0:
        print("\n⚠️ No open ports found! Check:")
        print("   1. Is the target running?")
        print("   2. Can you ping the target?")
        print("   3. Are you running with sudo?")
        return None

    # Step 3: AI Analysis
    print("\n" + "=" * 60)
    print("🧠 Step 3: AI Threat Analysis")
    print("=" * 60)
    ai_analysis, threat_summary = ai.analyze_full_scan(scan_results)

    print(f"\n🎯 Threat Assessment:")
    print(f"   Critical: {threat_summary['critical']}")
    print(f"   High:     {threat_summary['high']}")
    print(f"   Medium:   {threat_summary['medium']}")
    print(f"   Low:      {threat_summary['low']}")
    print(f"   Safe:     {threat_summary['safe']}")
    print(f"   AI Avg Confidence: {threat_summary['ai_confidence_avg']}%")

    # Step 4: Attack Simulation
    print("\n" + "=" * 60)
    print("⚔️  Step 4: Automated Attack Simulation")
    print("=" * 60)
    simulator = AttackSimulator(target)
    attack_report = simulator.run_full_assessment(ai_analysis, threat_summary)

    # Step 5: Generate Report
    print("\n" + "=" * 60)
    print("📄 Step 5: Generating Report")
    print("=" * 60)
    report_path = reporter.generate(
        scan_results=scan_results,
        ai_analysis=ai_analysis,
        threat_summary=threat_summary,
        attack_report=attack_report,
        target_ip=target
    )

    # Final Summary
    print("\n" + "=" * 60)
    print("✅ ASSESSMENT COMPLETE!")
    print("=" * 60)
    print(f"   📊 Findings:    {threat_summary['total_findings']}")
    print(f"   🔴 Critical:    {threat_summary['critical']}")
    print(f"   ⚔️  Attacks:     {attack_report['successful_attacks']}/{attack_report['total_attacks']} succeeded")
    print(f"   💀 Exploited:   {len(attack_report['critical_findings'])} critical")
    print(f"   📄 Report:      {report_path}")
    print(f"   🌐 Dashboard:   Run: python3 app.py → http://localhost:8080")
    print("=" * 60)

    # Save JSON results
    json_path = f"reports/results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_path, 'w') as f:
        json.dump({
            'scan': scan_results,
            'ai_analysis': ai_analysis,
            'threat_summary': threat_summary,
            'attack_report': attack_report,
        }, f, indent=2, default=str)
    print(f"   📋 JSON Data:   {json_path}")

    return {
        'scan_results': scan_results,
        'ai_analysis': ai_analysis,
        'threat_summary': threat_summary,
        'attack_report': attack_report,
        'report_path': report_path,
    }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("\n🛡️  AI-Sentinel v2.0")
        print("    Usage: sudo python3 main.py <TARGET_IP>")
        print("    Example: sudo python3 main.py 192.168.56.101")
        print("    Dashboard: python3 app.py")
        sys.exit(1)

    target = sys.argv[1]
    run_assessment(target)
