#!/usr/bin/env python3
"""
AI-Sentinel Network Scanner Engine
Discovers hosts, ports, services and OS using Nmap
"""

import nmap
import time
from datetime import datetime


class NetworkScanner:

    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_history = []
        self.last_results = []

    def quick_scan(self, target):
        print(f"\n [QUICK SCAN] Scanning {target}...")
        start = time.time()
        try:
            self.nm.scan(
                hosts=target,
                arguments='-sV -sC --top-ports 200 -O --open -T4'
            )
        except nmap.PortScannerError as e:
            print(f" Nmap error: {e}")
            print(" Try running with sudo: sudo python3 main.py <target>")
            return []
        elapsed = round(time.time() - start, 2)
        results = self._parse_results(target, "quick", elapsed)
        print(f" Quick scan done in {elapsed}s — {self._count_ports(results)} ports found")
        return results

    def deep_scan(self, target):
        print(f"\n [DEEP SCAN] Scanning all ports on {target}...")
        start = time.time()
        try:
            self.nm.scan(
                hosts=target,
                arguments='-sV -sC -p- -O --open -T4 --version-intensity 5'
            )
        except nmap.PortScannerError as e:
            print(f" Nmap error: {e}")
            return []
        elapsed = round(time.time() - start, 2)
        results = self._parse_results(target, "deep", elapsed)
        print(f" Deep scan done in {elapsed}s — {self._count_ports(results)} ports found")
        return results

    def targeted_scan(self, target, ports):
        port_str = ','.join(map(str, ports))
        print(f"\n [TARGETED] Scanning ports {port_str} on {target}...")
        start = time.time()
        try:
            self.nm.scan(
                hosts=target,
                arguments=f'-sV -sC -p {port_str} -O -A --open'
            )
        except nmap.PortScannerError as e:
            print(f" Nmap error: {e}")
            return []
        elapsed = round(time.time() - start, 2)
        results = self._parse_results(target, "targeted", elapsed)
        print(f" Targeted scan done in {elapsed}s")
        return results

    def adaptive_scan(self, target):
        """
        AI-GUIDED ADAPTIVE SCANNING
        Phase 1: Quick scan to discover open ports
        Phase 2: Deep enumeration on discovered ports
        Phase 3: Vulnerability scripts on high-risk services
        """
        print(f"\n [ADAPTIVE SCAN] AI-guided scanning of {target}...")

        # Phase 1
        print("   Phase 1: Quick port discovery...")
        phase1 = self.quick_scan(target)

        discovered_ports = []
        for host in phase1:
            for port_info in host['ports']:
                discovered_ports.append(port_info['port'])

        if not discovered_ports:
            print(" No open ports found!")
            return phase1

        # Phase 2
        print(f"  Phase 2: Deep enumeration of {len(discovered_ports)} ports...")
        phase2 = self.targeted_scan(target, discovered_ports)

        # Phase 3
        interesting_services = ['http', 'https', 'ssh', 'ftp', 'smb',
                                'mysql', 'rdp', 'vnc', 'telnet',
                                'microsoft-ds', 'netbios-ssn', 'postgresql',
                                'irc', 'java-rmi', 'ajp13']

        vuln_ports = []
        for host in phase2:
            for port_info in host['ports']:
                if port_info['service'] in interesting_services:
                    vuln_ports.append(port_info['port'])

        if vuln_ports:
            vuln_port_str = ','.join(map(str, vuln_ports[:15]))
            print(f"  Phase 3: Vulnerability scripts on {len(vuln_ports[:15])} services...")
            try:
                self.nm.scan(
                    hosts=target,
                    arguments=f'--script=vuln,exploit -p {vuln_port_str} --open -Pn'
                )
                vuln_results = self._parse_results(target, "vuln", 0)

                for v_host in vuln_results:
                    for p2_host in phase2:
                        if v_host['ip'] == p2_host['ip']:
                            for v_port in v_host['ports']:
                                for p2_port in p2_host['ports']:
                                    if v_port['port'] == p2_port['port']:
                                        p2_port['vulns'] = v_port.get('vulns', [])
            except Exception as e:
                print(f"   Vuln scan warning: {str(e)[:100]}")

        print(f"  Adaptive scan complete!")
        self.last_results = phase2
        return phase2

    def _parse_results(self, target, scan_type, elapsed):
        results = []
        for host in self.nm.all_hosts():
            os_matches = self.nm[host].get('osmatch', [])
            os_name = os_matches[0]['name'] if os_matches else 'Unknown'

            host_data = {
                'ip': host,
                'hostname': self.nm[host].hostname() or 'N/A',
                'state': self.nm[host].state(),
                'os': os_name,
                'scan_type': scan_type,
                'scan_time': datetime.now().isoformat(),
                'ports': []
            }

            for proto in self.nm[host].all_protocols():
                for port in sorted(self.nm[host][proto].keys()):
                    port_data = self.nm[host][proto][port]

                    vulns = []
                    if 'script' in port_data:
                        for script_name, output in port_data['script'].items():
                            vulns.append({
                                'name': script_name,
                                'output': str(output)[:500]
                            })

                    host_data['ports'].append({
                        'port': port,
                        'protocol': proto,
                        'state': port_data['state'],
                        'service': port_data['name'],
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extra': port_data.get('extrainfo', ''),
                        'vulns': vulns,
                    })

            results.append(host_data)

        self.scan_history.append({
            'target': target,
            'scan_type': scan_type,
            'elapsed': elapsed,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })

        return results

    def _count_ports(self, results):
        return sum(len(h['ports']) for h in results)

    def get_summary(self, results):
        total_ports = 0
        services = {}
        risk_ports = []

        HIGH_RISK = {21, 23, 135, 139, 445, 1433, 1524, 3389, 4444, 5900, 6667, 31337}
        MEDIUM_RISK = {25, 110, 143, 512, 513, 514, 1099, 1723, 2049, 3306, 3632, 5432, 8080, 8180}

        for host in results:
            for port_info in host['ports']:
                total_ports += 1
                svc = port_info['service']
                services[svc] = services.get(svc, 0) + 1

                if port_info['port'] in HIGH_RISK:
                    risk_ports.append({**port_info, 'risk': 'HIGH'})
                elif port_info['port'] in MEDIUM_RISK:
                    risk_ports.append({**port_info, 'risk': 'MEDIUM'})

        return {
            'total_ports': total_ports,
            'total_hosts': len(results),
            'services': services,
            'risk_ports': risk_ports,
            'scan_time': datetime.now().isoformat()
        }

