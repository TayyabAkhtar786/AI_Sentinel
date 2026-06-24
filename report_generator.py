#!/usr/bin/env python3
"""
AI-Sentinel Premium v3.0 — Professional PDF Report Generator
Generates enterprise-grade security assessment reports
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.units import inch, mm
from datetime import datetime
import os


class ReportGenerator:

    COLORS = {
        'primary': colors.HexColor('#0a0e17'),
        'accent': colors.HexColor('#3b82f6'),
        'critical': colors.HexColor('#ef4444'),
        'high': colors.HexColor('#f59e0b'),
        'medium': colors.HexColor('#eab308'),
        'low': colors.HexColor('#10b981'),
        'safe': colors.HexColor('#3b82f6'),
        'dark': colors.HexColor('#1a1f35'),
        'text': colors.HexColor('#333333'),
        'light_bg': colors.HexColor('#f8f9fa'),
        'purple': colors.HexColor('#a855f7'),
    }

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            name='ReportTitle', fontSize=28, textColor=self.COLORS['primary'],
            spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle', fontSize=14, textColor=self.COLORS['accent'],
            spaceAfter=20, alignment=TA_CENTER, fontName='Helvetica'
        ))
        self.styles.add(ParagraphStyle(
            name='SectionTitle', fontSize=16, textColor=self.COLORS['primary'],
            spaceBefore=25, spaceAfter=12, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='SubSection', fontSize=13, textColor=self.COLORS['dark'],
            spaceBefore=15, spaceAfter=8, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='BodyText2', fontSize=10, textColor=self.COLORS['text'],
            spaceAfter=6, leading=14, alignment=TA_JUSTIFY, fontName='Helvetica'
        ))
        self.styles.add(ParagraphStyle(
            name='Finding', fontSize=10, textColor=self.COLORS['text'],
            spaceAfter=4, leading=13, leftIndent=20, fontName='Helvetica'
        ))
        self.styles.add(ParagraphStyle(
            name='CriticalText', fontSize=10, textColor=self.COLORS['critical'],
            fontName='Helvetica-Bold', spaceAfter=4
        ))
        self.styles.add(ParagraphStyle(
            name='Footer', fontSize=8, textColor=colors.grey, alignment=TA_CENTER
        ))

    def _header_line(self, story):
        story.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['accent'], spaceAfter=10))

    def _thin_line(self, story):
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=5, spaceAfter=5))

    def _safe_get(self, d, *keys, default='N/A'):
        """Safely get value from dict trying multiple key names"""
        if not isinstance(d, dict):
            return default
        for key in keys:
            if key in d:
                val = d[key]
                if val is not None:
                    return val
        return default

    def _safe_str(self, val, max_len=200):
        """Safely convert any value to string"""
        if val is None:
            return 'N/A'
        s = str(val)
        if len(s) > max_len:
            s = s[:max_len] + '...'
        # Escape XML special characters for reportlab
        s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return s

    def generate(self, scan_results, ai_analysis, threat_summary,
                 attack_report, target_ip, output_path=None):

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/AI_Sentinel_Report_{timestamp}.pdf"

        os.makedirs('reports', exist_ok=True)

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            topMargin=25*mm, bottomMargin=25*mm,
            leftMargin=20*mm, rightMargin=20*mm
        )

        story = []
        now = datetime.now()

        # Safe access helpers
        if not threat_summary:
            threat_summary = {}
        if not attack_report:
            attack_report = {}

        total = threat_summary.get('total_findings', 0)
        crit = threat_summary.get('critical', 0)
        high = threat_summary.get('high', 0)
        med = threat_summary.get('medium', 0)
        low = threat_summary.get('low', 0)
        safe = threat_summary.get('safe', 0)
        anomalies = threat_summary.get('anomalies_detected', 0)

        if crit > 0:
            overall_risk = 'CRITICAL'
        elif high > 0:
            overall_risk = 'HIGH'
        elif med > 0:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'

        # ════════════════════════════════════════
        # COVER PAGE
        # ════════════════════════════════════════

        story.append(Spacer(1, 1.5*inch))
        story.append(Paragraph("🛡️", ParagraphStyle('icon', fontSize=50, alignment=TA_CENTER)))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("AI-SENTINEL PREMIUM v3.0", self.styles['ReportTitle']))
        story.append(Paragraph("AI-Powered Security Assessment Report", self.styles['ReportSubtitle']))
        self._header_line(story)
        story.append(Spacer(1, 0.5*inch))

        cover_data = [
            ['Target:', str(target_ip)],
            ['Date:', now.strftime("%B %d, %Y")],
            ['Time:', now.strftime("%H:%M:%S")],
            ['Classification:', 'CONFIDENTIAL'],
            ['AI Engine:', 'Hybrid (Random Forest + Isolation Forest)'],
            ['AI Accuracy:', str(threat_summary.get('ai_model_accuracy', 'N/A'))],
            ['Methodology:', str(threat_summary.get('ai_methodology', 'Hybrid AI'))],
        ]
        cover_table = Table(cover_data, colWidths=[150, 300])
        cover_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), self.COLORS['dark']),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.lightgrey),
        ]))
        story.append(cover_table)
        story.append(Spacer(1, 0.8*inch))

        # Risk Overview Box
        risk_data = [
            ['OVERALL RISK RATING', overall_risk],
            ['Total Findings', str(total)],
            ['Critical', str(crit)],
            ['High', str(high)],
            ['Medium', str(med)],
            ['Low', str(low)],
            ['Safe', str(safe)],
            ['Anomalies Detected', str(anomalies)],
        ]
        risk_table = Table(risk_data, colWidths=[250, 200])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('TEXTCOLOR', (1, 0), (1, 0), self.COLORS['critical'] if crit > 0 else self.COLORS['accent']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('FONTSIZE', (0, 1), (-1, -1), 11),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.COLORS['light_bg'], colors.white]),
        ]))
        story.append(risk_table)
        story.append(PageBreak())

        # ════════════════════════════════════════
        # TABLE OF CONTENTS
        # ════════════════════════════════════════

        story.append(Paragraph("TABLE OF CONTENTS", self.styles['SectionTitle']))
        self._header_line(story)
        toc = [
            "1. Executive Summary",
            "2. Methodology",
            "3. AI Model Details",
            "4. Scan Results &amp; AI Analysis",
            "5. Attack Simulation Results",
            "6. Critical Findings Detail",
            "7. Recommendations",
            "8. Conclusion",
        ]
        for item in toc:
            story.append(Paragraph(item, self.styles['BodyText2']))
        story.append(PageBreak())

        # ════════════════════════════════════════
        # 1. EXECUTIVE SUMMARY
        # ════════════════════════════════════════

        story.append(Paragraph("1. EXECUTIVE SUMMARY", self.styles['SectionTitle']))
        self._header_line(story)

        atk_total = attack_report.get('total_attacks', 0)
        atk_success = attack_report.get('successful_attacks', 0)
        atk_critical = len(attack_report.get('critical_findings', []))

        exec_text = (
            f"An AI-powered security assessment was conducted against <b>{self._safe_str(target_ip)}</b> "
            f"on <b>{now.strftime('%B %d, %Y')}</b>. The assessment utilized a <b>Hybrid AI Engine</b> "
            f"combining supervised machine learning (Random Forest Classifier) and unsupervised anomaly "
            f"detection (Isolation Forest) for comprehensive threat assessment."
            f"<br/><br/>"
            f"The AI engine identified <b>{total} findings</b>, classifying "
            f"<b>{crit} as Critical</b>, <b>{high} as High</b>, "
            f"<b>{med} as Medium</b>, and <b>{low} as Low</b> risk. "
            f"The anomaly detector flagged <b>{anomalies} unusual patterns</b>."
            f"<br/><br/>"
            f"The automated attack simulation performed <b>{atk_total} attacks</b>, "
            f"of which <b>{atk_success} were successful</b>. "
            f"<b>{atk_critical} critical vulnerabilities</b> were confirmed exploitable."
            f"<br/><br/>"
            f"The overall risk rating is <b>{overall_risk}</b>. "
            f"Immediate remediation is recommended for all critical and high-risk findings."
        )
        story.append(Paragraph(exec_text, self.styles['BodyText2']))
        story.append(Spacer(1, 0.3*inch))

        # Stats table
        stats_data = [
            ['Metric', 'Value'],
            ['Total Open Ports', str(total)],
            ['AI Confidence', f"{threat_summary.get('ai_confidence_avg', 0)}%"],
            ['Anomalies Detected', str(anomalies)],
            ['Attacks Performed', str(atk_total)],
            ['Successful Exploits', str(atk_success)],
            ['Critical Findings', str(atk_critical)],
            ['Overall Risk', overall_risk],
        ]
        stats_table = Table(stats_data, colWidths=[250, 200])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['dark']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.COLORS['light_bg'], colors.white]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(stats_table)
        story.append(PageBreak())

        # ════════════════════════════════════════
        # 2. METHODOLOGY
        # ════════════════════════════════════════

        story.append(Paragraph("2. METHODOLOGY", self.styles['SectionTitle']))
        self._header_line(story)

        story.append(Paragraph("2.1 Hybrid AI Assessment Approach", self.styles['SubSection']))
        story.append(Paragraph(
            "This assessment employed a Hybrid AI-driven methodology consisting of four phases:",
            self.styles['BodyText2']
        ))

        phases = [
            "<b>Phase 1 — AI-Guided Adaptive Scanning:</b> Multi-phase port discovery "
            "and service enumeration using Nmap with intelligent scan selection.",
            "<b>Phase 2 — Hybrid ML Threat Classification:</b> A Random Forest Classifier "
            "(supervised) combined with Isolation Forest (unsupervised anomaly detection) "
            "analyzed each service to produce hybrid risk scores.",
            "<b>Phase 3 — Automated Attack Simulation:</b> AI-guided exploit selection "
            "and execution against identified vulnerabilities.",
            "<b>Phase 4 — Report Generation:</b> Automated compilation of findings with "
            "AI-generated executive summary and recommendations.",
        ]
        for phase in phases:
            story.append(Paragraph(f"{phase}", self.styles['Finding']))
            story.append(Spacer(1, 0.1*inch))

        story.append(PageBreak())

        # ════════════════════════════════════════
        # 3. AI MODEL DETAILS
        # ════════════════════════════════════════

        story.append(Paragraph("3. AI MODEL DETAILS", self.styles['SectionTitle']))
        self._header_line(story)

        story.append(Paragraph(
            "The threat classification engine implements a <b>Hybrid AI approach</b> combining "
            "supervised classification with unsupervised anomaly detection.",
            self.styles['BodyText2']
        ))

        model_data = [
            ['Parameter', 'Value'],
            ['Supervised Model', 'Random Forest Classifier (200 trees, depth 15)'],
            ['Unsupervised Model', 'Isolation Forest (150 estimators, 10% contamination)'],
            ['Hybrid Scoring', '70% Supervised + 30% Anomaly + Expert Rules'],
            ['Training Samples', '3,000 (balanced across 5 classes)'],
            ['Features', '11 cybersecurity-specific features'],
            ['Test Split', '20% holdout'],
            ['Accuracy', str(threat_summary.get('ai_model_accuracy', 'N/A'))],
            ['Risk Categories', 'Safe, Low, Medium, High, Critical'],
            ['Explainable AI', 'Human-readable reasons for each classification'],
        ]
        model_table = Table(model_data, colWidths=[160, 290])
        model_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['dark']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.COLORS['light_bg'], colors.white]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(model_table)

        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("3.1 Feature Engineering", self.styles['SubSection']))
        story.append(Paragraph(
            "The model uses 11 engineered features: port number, well-known port flag, "
            "registered port flag, dynamic port flag, port risk score, service risk score, "
            "protocol type, version availability, backdoor port indicator, database port "
            "indicator, and remote access indicator.",
            self.styles['BodyText2']
        ))

        story.append(Paragraph("3.2 Anomaly Detection", self.styles['SubSection']))
        story.append(Paragraph(
            f"The Isolation Forest detected <b>{anomalies} anomalous service patterns</b> "
            f"that deviate from normal network behavior, potentially indicating unknown "
            f"threats or misconfigurations not covered by supervised training data.",
            self.styles['BodyText2']
        ))

        story.append(PageBreak())

        # ════════════════════════════════════════
        # 4. SCAN RESULTS & AI ANALYSIS
        # ════════════════════════════════════════

        story.append(Paragraph("4. SCAN RESULTS &amp; AI ANALYSIS", self.styles['SectionTitle']))
        self._header_line(story)

        if ai_analysis:
            for host in ai_analysis:
                if not isinstance(host, dict):
                    continue

                host_ip = self._safe_get(host, 'ip', default='Unknown')
                host_os = self._safe_get(host, 'os', default='Unknown')

                story.append(Paragraph(
                    f"Host: <b>{self._safe_str(host_ip)}</b> — OS: {self._safe_str(host_os)}",
                    self.styles['SubSection']
                ))

                ports = host.get('ports', [])
                if ports and isinstance(ports, list):
                    table_data = [['Port', 'Service', 'Version', 'AI Risk', 'Confidence', 'Anomaly']]

                    for p in ports:
                        if not isinstance(p, dict):
                            continue

                        port_num = self._safe_get(p, 'port', default='?')
                        proto = self._safe_get(p, 'protocol', default='tcp')
                        service = self._safe_get(p, 'service', default='unknown')
                        product = self._safe_get(p, 'product', default='')
                        version = self._safe_get(p, 'version', default='')
                        prod_ver = f"{product} {version}".strip() or 'N/A'

                        risk = self._safe_get(p, 'ai_risk_label', 'risk_label', 'risk', default='N/A')
                        confidence = self._safe_get(p, 'ai_confidence', 'confidence', default=0)
                        is_anomaly = self._safe_get(p, 'ai_is_anomaly', 'is_anomaly', default=False)

                        anomaly_text = 'YES' if is_anomaly else 'No'

                        table_data.append([
                            self._safe_str(f"{port_num}/{proto}", 20),
                            self._safe_str(service, 20),
                            self._safe_str(prod_ver, 30),
                            self._safe_str(risk, 15),
                            f"{confidence}%",
                            anomaly_text
                        ])

                    if len(table_data) > 1:
                        col_widths = [50, 60, 100, 55, 55, 45]
                        ftable = Table(table_data, colWidths=col_widths)

                        tstyle = [
                            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['dark']),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.COLORS['light_bg'], colors.white]),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                            ('TOPPADDING', (0, 0), (-1, -1), 4),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ]

                        for i, row in enumerate(table_data[1:], 1):
                            risk_val = row[3]
                            if 'Critical' in str(risk_val):
                                tstyle.append(('TEXTCOLOR', (3, i), (3, i), self.COLORS['critical']))
                                tstyle.append(('FONTNAME', (3, i), (3, i), 'Helvetica-Bold'))
                            elif 'High' in str(risk_val):
                                tstyle.append(('TEXTCOLOR', (3, i), (3, i), self.COLORS['high']))
                            if row[5] == 'YES':
                                tstyle.append(('TEXTCOLOR', (5, i), (5, i), self.COLORS['purple']))
                                tstyle.append(('FONTNAME', (5, i), (5, i), 'Helvetica-Bold'))

                        ftable.setStyle(TableStyle(tstyle))
                        story.append(ftable)
                        story.append(Spacer(1, 0.2*inch))

        story.append(PageBreak())

        # ════════════════════════════════════════
        # 5. ATTACK SIMULATION RESULTS
        # ════════════════════════════════════════

        story.append(Paragraph("5. ATTACK SIMULATION RESULTS", self.styles['SectionTitle']))
        self._header_line(story)

        if attack_report and isinstance(attack_report, dict):
            atk_summary = [
                ['Metric', 'Value'],
                ['Total Attacks', str(attack_report.get('total_attacks', 0))],
                ['Successful', str(attack_report.get('successful_attacks', 0))],
                ['Failed/Blocked', str(attack_report.get('failed_attacks', 0))],
                ['Critical Findings', str(len(attack_report.get('critical_findings', [])))],
            ]

            start_time = attack_report.get('start_time', 'N/A')
            end_time = attack_report.get('end_time', 'N/A')
            if isinstance(start_time, str) and len(start_time) > 19:
                start_time = start_time[:19]
            if isinstance(end_time, str) and len(end_time) > 19:
                end_time = end_time[:19]

            atk_summary.append(['Start Time', str(start_time)])
            atk_summary.append(['End Time', str(end_time)])

            atk_table = Table(atk_summary, colWidths=[250, 200])
            atk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['dark']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.COLORS['light_bg'], colors.white]),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(atk_table)
            story.append(Spacer(1, 0.2*inch))

            # Attack details
            attacks_performed = attack_report.get('attacks_performed', [])
            if attacks_performed and isinstance(attacks_performed, list):
                story.append(Paragraph("5.1 Attack Details", self.styles['SubSection']))

                atk_detail = [['#', 'Attack', 'Target', 'Status', 'Severity']]
                for i, atk in enumerate(attacks_performed[:30], 1):
                    if not isinstance(atk, dict):
                        continue
                    status = 'SUCCESS' if atk.get('success') else 'BLOCKED'
                    severity = self._safe_get(atk, 'severity', default='INFO')
                    attack_name = self._safe_str(self._safe_get(atk, 'attack', default='N/A'), 35)
                    attack_target = self._safe_str(self._safe_get(atk, 'target', default='N/A'), 20)

                    atk_detail.append([str(i), attack_name, attack_target, status, str(severity)])

                if len(atk_detail) > 1:
                    atk_detail_table = Table(atk_detail, colWidths=[25, 165, 85, 65, 55])
                    detail_style = [
                        ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['dark']),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 7),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.COLORS['light_bg'], colors.white]),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                        ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ]

                    for i, row in enumerate(atk_detail[1:], 1):
                        if row[4] == 'CRITICAL':
                            detail_style.append(('TEXTCOLOR', (4, i), (4, i), self.COLORS['critical']))
                        elif row[4] == 'HIGH':
                            detail_style.append(('TEXTCOLOR', (4, i), (4, i), self.COLORS['high']))

                    atk_detail_table.setStyle(TableStyle(detail_style))
                    story.append(atk_detail_table)
        else:
            story.append(Paragraph("No attack simulation was performed.", self.styles['BodyText2']))

        story.append(PageBreak())

        # ════════════════════════════════════════
        # 6. CRITICAL FINDINGS DETAIL
        # ════════════════════════════════════════

        story.append(Paragraph("6. CRITICAL FINDINGS DETAIL", self.styles['SectionTitle']))
        self._header_line(story)

        # Get top threats from threat_summary
        top_threats = threat_summary.get('top_threats', [])

        # Also get critical findings from attack report
        critical_findings = attack_report.get('critical_findings', []) if attack_report else []

        if top_threats and isinstance(top_threats, list):
            story.append(Paragraph("6.1 AI-Identified Top Threats", self.styles['SubSection']))

            for i, threat in enumerate(top_threats[:10], 1):
                if not isinstance(threat, dict):
                    continue

                t_host = self._safe_get(threat, 'host', 'ip', default='Unknown')
                t_port = self._safe_get(threat, 'port', default='?')
                t_service = self._safe_get(threat, 'service', default='unknown')
                t_risk = self._safe_get(threat, 'risk_label', 'risk', default='Unknown')
                t_conf = self._safe_get(threat, 'confidence', 'ai_confidence', default=0)
                t_anomaly = self._safe_get(threat, 'is_anomaly', 'ai_is_anomaly', default=False)

                story.append(Paragraph(
                    f"<b>Threat {i}:</b> {self._safe_str(t_host)}:{t_port} ({self._safe_str(t_service)}) "
                    f"— Risk: <b>{self._safe_str(t_risk)}</b> "
                    f"(Confidence: {t_conf}%)"
                    f"{' | ANOMALY DETECTED' if t_anomaly else ''}",
                    self.styles['Finding']
                ))

                # Show explanations
                explanations = threat.get('explanation', [])
                if isinstance(explanations, list):
                    for exp in explanations[:3]:
                        story.append(Paragraph(
                            f"  → {self._safe_str(exp, 150)}",
                            self.styles['Finding']
                        ))
                elif isinstance(explanations, str):
                    story.append(Paragraph(
                        f"  → {self._safe_str(explanations, 150)}",
                        self.styles['Finding']
                    ))

                self._thin_line(story)

        if critical_findings and isinstance(critical_findings, list):
            story.append(Paragraph("6.2 Confirmed Exploitable Vulnerabilities", self.styles['SubSection']))

            for i, finding in enumerate(critical_findings[:10], 1):
                if not isinstance(finding, dict):
                    continue

                f_attack = self._safe_get(finding, 'attack', default='N/A')
                f_target = self._safe_get(finding, 'target', default='N/A')
                f_severity = self._safe_get(finding, 'severity', default='N/A')

                story.append(Paragraph(
                    f"<b>{i}. {self._safe_str(f_attack, 80)}</b>",
                    self.styles['SubSection']
                ))
                story.append(Paragraph(
                    f"Target: {self._safe_str(f_target)} | Severity: <b>{self._safe_str(f_severity)}</b> | Status: Exploited",
                    self.styles['Finding']
                ))

                details = finding.get('details', {})
                if isinstance(details, dict):
                    for key, value in list(details.items())[:5]:
                        if isinstance(value, str) and len(value) < 150:
                            story.append(Paragraph(
                                f"  → <b>{self._safe_str(key, 30)}:</b> {self._safe_str(value, 120)}",
                                self.styles['Finding']
                            ))
                        elif isinstance(value, bool):
                            story.append(Paragraph(
                                f"  → <b>{self._safe_str(key, 30)}:</b> {'Yes' if value else 'No'}",
                                self.styles['Finding']
                            ))

                self._thin_line(story)

        if not top_threats and not critical_findings:
            story.append(Paragraph("No critical findings identified.", self.styles['BodyText2']))

        story.append(PageBreak())

        # ════════════════════════════════════════
        # 7. RECOMMENDATIONS
        # ════════════════════════════════════════

        story.append(Paragraph("7. RECOMMENDATIONS", self.styles['SectionTitle']))
        self._header_line(story)

        story.append(Paragraph("7.1 Immediate Actions (Critical)", self.styles['SubSection']))
        for rec in [
            "Patch or disable all services with confirmed backdoors (vsftpd, UnrealIRCd, Ingreslock)",
            "Remove or restrict access to services with empty/default credentials",
            "Disable Telnet and R-services (rexec, rlogin, rsh) — use SSH instead",
            "Fix SQL injection and command injection vulnerabilities in web applications",
            "Restrict NFS shares — remove world-readable exports",
        ]:
            story.append(Paragraph(f"• {rec}", self.styles['CriticalText']))

        story.append(Paragraph("7.2 Short-Term Actions (High Priority)", self.styles['SubSection']))
        for rec in [
            "Implement network segmentation to isolate critical services",
            "Enable multi-factor authentication on administrative interfaces",
            "Add security headers to all web servers (CSP, X-Frame-Options, HSTS)",
            "Update all software to latest patched versions",
            "Configure rate limiting on authentication endpoints",
        ]:
            story.append(Paragraph(f"• {rec}", self.styles['Finding']))

        story.append(Paragraph("7.3 Long-Term Actions (Best Practice)", self.styles['SubSection']))
        for rec in [
            "Deploy Intrusion Detection System (IDS/IPS) for continuous monitoring",
            "Implement centralized logging with SIEM solution",
            "Conduct regular vulnerability assessments and penetration tests",
            "Establish patch management program",
            "Develop and test incident response plan",
            "Use encrypted protocols everywhere (SSH, SFTP, HTTPS)",
        ]:
            story.append(Paragraph(f"• {rec}", self.styles['Finding']))

        story.append(PageBreak())

        # ════════════════════════════════════════
        # 8. CONCLUSION
        # ════════════════════════════════════════

        story.append(Paragraph("8. CONCLUSION", self.styles['SectionTitle']))
        self._header_line(story)

        # Executive summary from AI
        exec_summary = threat_summary.get('executive_summary', '')
        if exec_summary and isinstance(exec_summary, str):
            story.append(Paragraph("8.1 AI-Generated Executive Summary", self.styles['SubSection']))
            for line in exec_summary.split('\n'):
                line = line.strip()
                if line:
                    story.append(Paragraph(self._safe_str(line, 500), self.styles['BodyText2']))
            story.append(Spacer(1, 0.2*inch))

        conclusion = (
            f"The AI-powered security assessment of <b>{self._safe_str(target_ip)}</b> revealed a "
            f"<b>{overall_risk}</b> overall risk posture. "
            f"The Hybrid AI Engine identified <b>{total} findings</b>, with "
            f"<b>{crit} critical</b> and <b>{high} high</b> risk issues. "
            f"The Isolation Forest anomaly detector flagged <b>{anomalies} unusual patterns</b> "
            f"for further investigation."
            f"<br/><br/>"
            f"The automated attack simulation successfully exploited "
            f"<b>{atk_success} out of {atk_total}</b> tested attack vectors. "
            f"The AI classifier operated with <b>{threat_summary.get('ai_confidence_avg', 0)}%</b> "
            f"average confidence using a hybrid supervised + unsupervised approach."
            f"<br/><br/>"
            f"Immediate remediation of all critical and high-risk findings is strongly recommended."
        )
        story.append(Paragraph("8.2 Summary", self.styles['SubSection']))
        story.append(Paragraph(conclusion, self.styles['BodyText2']))

        story.append(Spacer(1, 1*inch))
        self._header_line(story)
        story.append(Paragraph(
            f"Report generated by AI-Sentinel Premium v3.0 on {now.strftime('%B %d, %Y at %H:%M:%S')}<br/>"
            f"AI Engine: Hybrid (Random Forest + Isolation Forest) | Accuracy: {threat_summary.get('ai_model_accuracy', 'N/A')}<br/>"
            f"This report is confidential and intended for authorized personnel only.",
            self.styles['Footer']
        ))

        # BUILD PDF
        try:
            doc.build(story)
            print(f"\n📄 Report saved: {output_path}")
        except Exception as e:
            print(f"❌ PDF build error: {e}")
            import traceback
            traceback.print_exc()
            # Try simpler report
            try:
                simple_story = [
                    Paragraph("AI-Sentinel Security Report", self.styles['ReportTitle']),
                    Spacer(1, 0.5*inch),
                    Paragraph(f"Target: {target_ip}", self.styles['BodyText2']),
                    Paragraph(f"Date: {now.strftime('%B %d, %Y')}", self.styles['BodyText2']),
                    Paragraph(f"Findings: {total}", self.styles['BodyText2']),
                    Paragraph(f"Critical: {crit} | High: {high} | Medium: {med}", self.styles['BodyText2']),
                    Paragraph(f"Risk: {overall_risk}", self.styles['BodyText2']),
                ]
                doc2 = SimpleDocTemplate(output_path, pagesize=A4)
                doc2.build(simple_story)
                print(f"📄 Simplified report saved: {output_path}")
            except Exception as e2:
                print(f"❌ Even simple report failed: {e2}")
                raise

        return output_path
