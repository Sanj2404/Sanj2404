from flask import Flask, render_template_string, request, send_file
import os
from datetime import datetime, timedelta
import pdfkit
import tempfile
import json
import base64

app = Flask(__name__)

# Read and encode logo image
def get_logo_base64():
    """Convert logo image to base64 for embedding in HTML"""
    logo_path = "logo.png"  # Update this path to your logo file
    try:
        with open(logo_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            return encoded_string
    except FileNotFoundError:
        # If logo file doesn't exist, return None
        print(f"Warning: Logo file '{logo_path}' not found. Using text header instead.")
        return None

# Get logo base64 string
LOGO_BASE64 = get_logo_base64()

# Your HTML template (updated with CyberWacht branding)
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SECURITY AUDIT REPORT | {{ organization }} | {{ audit_period }}</title>
    <style>
        /* All your CSS styles here */
        @page {
            size: A4;
            margin: 2.5cm 2cm 2cm 2cm;
            @top-left {
                content: "SECURITY AUDIT REPORT";
                font-size: 10pt;
                color: #666;
            }
            @top-right {
                content: "CONFIDENTIAL";
                font-size: 10pt;
                color: #c00;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10pt;
                color: #666;
            }
        }

        @page :first {
            margin-top: 1.5cm;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Calibri', 'Arial', sans-serif;
        }

        body {
            font-size: 11pt;
            line-height: 1.4;
            color: #000;
            background: white;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }

        .pdf-page {
            width: 100%;
            position: relative;
            page-break-after: always;
            padding-top: 1.5cm;
            background: #ffffff;
        }

        .logo-container {
            text-align: center;
            margin-bottom: 1cm;
        }

        .logo {
            max-height: 1.5cm;
            max-width: 80%;
        }

        .report-header {
            text-align: center;
            margin-bottom: 1.5cm;
            position: relative;
        }

        .company-name {
            font-size: 32pt;
            font-weight: bold;
            color: #0d5ec4; /* CyberWacht blue */
            margin-bottom: 0.5cm;
            line-height: 1.1;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .report-title {
            font-size: 28pt;
            font-weight: bold;
            color: #000000;
            margin-bottom: 0.3cm;
            line-height: 1.2;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .report-subtitle {
            font-size: 16pt;
            color: #0d5ec4; /* CyberWacht blue */
            font-weight: 600;
            margin-bottom: 0.2cm;
            text-transform: uppercase;
        }

        .report-client {
            font-size: 18pt;
            font-weight: bold;
            color: #000000;
            margin-bottom: 0.3cm;
            margin-top: 1.5cm;
        }

        .report-date {
            font-size: 14pt;
            color: #666;
            margin-bottom: 0.5cm;
        }

        .meta-box {
            display: flex;
            justify-content: space-between;
            margin-top: 2cm;
            padding-top: 0.5cm;
            border-top: 2px solid #0d5ec4;
            width: 80%;
            margin-left: auto;
            margin-right: auto;
        }

        .meta-item {
            text-align: center;
            flex: 1;
        }

        .meta-label {
            font-size: 10pt;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 5px;
            font-weight: bold;
        }

        .meta-value {
            font-size: 12pt;
            font-weight: bold;
            color: #0d5ec4; /* CyberWacht blue */
        }

        .watermark {
            position: fixed;
            top: 40%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 80pt;
            color: rgba(13, 94, 196, 0.05); /* Light CyberWacht blue */
            font-weight: 900;
            pointer-events: none;
            z-index: -1000;
            opacity: 0.3;
        }

        .section {
            margin-bottom: 0.8cm;
        }

        .section-title {
            font-size: 16pt;
            font-weight: bold;
            color: #0d5ec4; /* CyberWacht blue */
            border-bottom: 2px solid #0d5ec4; /* CyberWacht blue */
            padding-bottom: 0.2cm;
            margin-bottom: 0.5cm;
            page-break-after: avoid;
        }

        .subsection-title {
            font-size: 13pt;
            font-weight: bold;
            color: #2a7dee; /* Lighter CyberWacht blue */
            margin-top: 0.6cm;
            margin-bottom: 0.3cm;
            padding-left: 0.3cm;
            border-left: 4px solid #0d5ec4; /* CyberWacht blue */
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 0.5cm 0;
            font-size: 10pt;
            border: 1px solid #ccc;
            page-break-inside: avoid;
        }

        th {
            background-color: #0d5ec4 !important; /* CyberWacht blue */
            color: white !important;
            font-weight: bold;
            padding: 0.3cm;
            text-align: left;
            border: 1px solid #0d5ec4; /* CyberWacht blue */
            font-size: 9pt;
        }

        td {
            padding: 0.3cm;
            border: 1px solid #ccc;
            vertical-align: top;
        }

        tr:nth-child(even) {
            background-color: #f5f5f5 !important;
        }

        .scorecard {
            background: linear-gradient(135deg, #0d5ec4, #2a7dee); /* CyberWacht blue gradient */
            color: white;
            padding: 0.8cm;
            border-radius: 0.3cm;
            text-align: center;
            margin: 0.5cm auto;
            width: 70%;
            border: 1px solid #0d5ec4;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            page-break-inside: avoid;
        }

        .grade-large {
            font-size: 36pt;
            font-weight: bold;
            margin-bottom: 0.2cm;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }

        .grade-label {
            font-size: 12pt;
            opacity: 0.9;
        }

        .improvement-badge {
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            padding: 0.1cm 0.3cm;
            border-radius: 1cm;
            font-size: 9pt;
            margin-top: 0.2cm;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .finding-card {
            border: 1px solid #ccc;
            border-radius: 0.2cm;
            margin-bottom: 0.5cm;
            page-break-inside: avoid;
        }

        .finding-header {
            background-color: #f0f7ff;
            padding: 0.4cm;
            border-bottom: 1px solid #ccc;
        }

        .finding-title {
            font-size: 12pt;
            font-weight: bold;
            color: #0d5ec4; /* CyberWacht blue */
            margin-bottom: 0.1cm;
        }

        .severity-badge {
            display: inline-block;
            padding: 0.1cm 0.3cm;
            border-radius: 0.2cm;
            font-size: 8pt;
            font-weight: bold;
            margin-right: 0.2cm;
        }

        .critical { background: #ffebee; color: #c00; border: 1px solid #c00; }
        .high { background: #fff3e0; color: #ff6f00; border: 1px solid #ff6f00; }
        .medium { background: #fff8e1; color: #ff8f00; border: 1px solid #ff8f00; }
        .low { background: #e8f5e9; color: #2e7d32; border: 1px solid #2e7d32; }

        .status-badge {
            display: inline-block;
            padding: 0.1cm 0.3cm;
            border-radius: 0.2cm;
            font-size: 8pt;
            font-weight: bold;
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #2e7d32;
        }

        .risk-score {
            float: right;
            font-weight: bold;
            padding: 0.1cm 0.3cm;
            background: #f5f5f5;
            border-radius: 0.2cm;
            border-left: 4px solid;
        }

        .risk-critical { border-left-color: #c00; }
        .risk-high { border-left-color: #ff6f00; }
        .risk-medium { border-left-color: #ff8f00; }
        .risk-low { border-left-color: #2e7d32; }

        .finding-body {
            padding: 0.4cm;
        }

        .finding-section {
            margin-bottom: 0.3cm;
        }

        .section-label {
            font-weight: bold;
            color: #0d5ec4; /* CyberWacht blue */
            margin-bottom: 0.1cm;
            font-size: 10pt;
        }

        .proof-box {
            background: #f9f9f9;
            padding: 0.3cm;
            border-left: 3px solid #2a7dee; /* Lighter CyberWacht blue */
            margin: 0.2cm 0;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
        }

        .remediation-box {
            background: #e8f5e9;
            padding: 0.3cm;
            border-left: 3px solid #2e7d32;
            margin: 0.2cm 0;
        }

        ul, ol {
            margin-left: 0.8cm;
            margin-bottom: 0.3cm;
        }

        li {
            margin-bottom: 0.1cm;
        }

        .page-break {
            page-break-before: always;
        }

        .keep-together {
            page-break-inside: avoid;
        }

        .break-before {
            page-break-before: always;
        }

        .report-footer {
            position: fixed;
            bottom: 1.5cm;
            left: 2cm;
            right: 2cm;
            text-align: center;
            font-size: 8pt;
            color: #666;
            border-top: 1px solid #ccc;
            padding-top: 0.2cm;
        }

        .signature-section {
            margin-top: 1.5cm;
            padding-top: 0.5cm;
            border-top: 2px solid #ccc;
        }

        .signature-grid {
            display: flex;
            justify-content: space-between;
            margin-top: 0.5cm;
        }

        .signature-box {
            text-align: center;
            flex: 1;
            padding: 0 0.5cm;
        }

        .signature-line {
            height: 1px;
            background: #000;
            margin: 0.8cm 0 0.2cm 0;
            width: 80%;
            display: inline-block;
        }

        @media print {
            body {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            .pdf-page {
                padding-top: 1cm;
            }

            .watermark {
                opacity: 0.1;
            }

            .no-print {
                display: none;
            }
        }

        .text-center { text-align: center; }
        .mb-10 { margin-bottom: 0.3cm; }
        .mb-20 { margin-bottom: 0.6cm; }
        .mb-30 { margin-bottom: 0.9cm; }
        .mt-20 { margin-top: 0.6cm; }
        .mt-30 { margin-top: 0.9cm; }
        .mt-40 { margin-top: 1.2cm; }
        
        /* New classes for better page control */
        .force-new-page {
            page-break-before: always !important;
        }
        
        .avoid-break-inside {
            page-break-inside: avoid !important;
        }
        
        .allow-break-inside {
            page-break-inside: auto !important;
        }
        
        .security-grade {
            font-size: 48pt;
            font-weight: bold;
            color: #0d5ec4;
            text-align: center;
            margin: 1cm 0;
        }
        
        .assessment-details {
            margin-top: 1.5cm;
            text-align: center;
        }
        
        .assessment-details p {
            margin: 0.3cm 0;
            font-size: 11pt;
        }
        
        .toc-page {
            page-break-after: always;
        }
        
        .doc-info-page {
            page-break-after: always;
        }
        .cover-page {
            position: relative;
            overflow: hidden;
            height: 25.2cm;
            border: 1px solid #ccc;
            background-color: white;
            box-shadow: 0 0 5px rgba(0,0,0,0.1);
            box-sizing: border-box; /* Include padding and border in the element's total width and height */
            padding: 1in; /* Inner padding for content */
            overflow: hidden;
        }
        
        .corner-decoration {
            position: absolute;
            width: 100px;
            height: 100px;
            background-color: #5ce98c;
            border-radius: 50%;
            z-index: 0;
        }
        .top-left {
            top: -50px;
            left: -50px;
        }
        .top-right {
            top: -50px;
            right: -50px;
        }
        .bottom-left {
            bottom: -50px;
            left: -50px;
        }
        .bottom-right {
            bottom: -50px;
            right: -50px;
        }
    </style>
</head>
<body>
<div class="pdf-page cover-page">
   <div class="corner-decoration top-left"></div>
   <div class="corner-decoration top-right"></div>
   <div class="corner-decoration bottom-left"></div>
   <div class="corner-decoration bottom-right"></div>
        <div class="watermark">CYBERWACHT</div>

        {% if logo_base64 %}
        <div class="logo-container">
            <img src="data:image/png;base64,{{ logo_base64 }}" class="logo" alt="CyberWacht Logo">
        </div>
        {% endif %}

        <div class="report-header">

            <div class="report-title">SECURITY AUDIT REPORT</div>
            <div class="report-subtitle">Vulnerability Assessment & Penetration Testing</div>
            <div class="report-client">{{ target_url }}</div>
            <div class="report-date">{{ audit_period }}</div>

            <div class="assessment-details">
                <p><strong>Assessment Period:</strong> {{ assessment_period }}</p>
                <p><strong>Assessment Type:</strong> {{ project_type }}</p>
                <p><strong>Organization:</strong> {{ organization }}</p>
            </div>

            <div class="security-grade">{{ final_grade }}</div>

            <div class="meta-box">
                <div class="meta-item">
                    <div class="meta-label">Report ID</div>
                    <div class="meta-value">{{ report_id }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Date</div>
                    <div class="meta-value">{{ report_date }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Classification</div>
                    <div class="meta-value">{{ classification }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Page 2: Table of Contents -->
    <div class="pdf-page toc-page">
        <div class="section">
            <div class="section-title">TABLE OF CONTENTS</div>

            <table class="avoid-break-inside">
                <tr>
                    <td width="80%"><strong>1. EXECUTIVE SUMMARY</strong></td>
                    <td>3</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">1.1 Project Overview</td>
                    <td>3</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">1.2 Primary Objectives</td>
                    <td>3</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">1.3 Project Details</td>
                    <td>4</td>
                </tr>
                <tr>
                    <td><strong>2. SCOPE OF ASSESSMENT</strong></td>
                    <td>5</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">2.1 Assessment Objectives</td>
                    <td>5</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">2.2 Target Assets</td>
                    <td>6</td>
                </tr>
                <tr>
                    <td><strong>3. SECURITY SCORECARD</strong></td>
                    <td>7</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">3.1 Vulnerability Distribution</td>
                    <td>7</td>
                </tr>
                <tr>
                    <td style="padding-left: 0.5cm;">3.2 Summary Statistics</td>
                    <td>8</td>
                </tr>
                <tr>
                    <td><strong>4. DETAILED VULNERABILITY FINDINGS</strong></td>
                    <td>9</td>
                </tr>
                {% set severity_sections = namespace(counter=1) %}
                {% for severity in ['Critical', 'High', 'Medium', 'Low'] %}
                    {% set vulns_in_severity = vulnerabilities|selectattr('severity', 'equalto', severity)|list %}
                    {% if vulns_in_severity %}
                    <tr>
                        <td style="padding-left: 0.5cm;">4.{{ severity_sections.counter }} {{ severity }} Severity Findings</td>
                        <td>{{ 9 + severity_sections.counter - 1 }}</td>
                    </tr>
                        {% set severity_sections.counter = severity_sections.counter + 1 %}
                    {% endif %}
                {% endfor %}
                <tr>
                    <td><strong>5. CONCLUSION</strong></td>
                    <td>{{ 9 + (vulnerabilities|length) // 2 + 2 }}</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Page 3: Document Information -->
    <div class="pdf-page doc-info-page">
        <div class="section">
            <div class="section-title">DOCUMENT INFORMATION</div>

            <table class="avoid-break-inside">
                <tr>
                    <td width="40%"><strong>Document Title:</strong></td>
                    <td>Security Audit Report</td>
                </tr>
                <tr>
                    <td><strong>Document Version:</strong></td>
                    <td>{{ document_version }}</td>
                </tr>
                <tr>
                    <td><strong>Classification:</strong></td>
                    <td>{{ classification }}</td>
                </tr>
                <tr>
                    <td><strong>Generated Date:</strong></td>
                    <td>{{ report_date }}</td>
                </tr>
                <tr>
                    <td><strong>Valid Until:</strong></td>
                    <td>{{ valid_until }}</td>
                </tr>
                <tr>
                    <td><strong>Distribution:</strong></td>
                    <td>{{ distribution }}</td>
                </tr>
                <tr>
                    <td><strong>Organization:</strong></td>
                    <td>{{ organization }}</td>
                </tr>
                <tr>
                    <td><strong>Target System:</strong></td>
                    <td>{{ target_url }}</td>
                </tr>
                <tr>
                    <td><strong>Security Engineer:</strong></td>
                    <td>{{ security_engineer }}</td>
                </tr>
                <tr>
                    <td><strong>Project Type:</strong></td>
                    <td>{{ project_type }}</td>
                </tr>
                <tr>
                    <td><strong>Audit Period:</strong></td>
                    <td>{{ audit_period }}</td>
                </tr>
                <tr>
                    <td><strong>Report ID:</strong></td>
                    <td>{{ report_id }}</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Page 4: Executive Summary -->
    <div class="pdf-page">
        <div class="section">
            <div class="section-title">1. EXECUTIVE SUMMARY</div>

            <div class="subsection-title">1.1 Project Overview</div>
            <p class="mb-20">{{ project_overview }}</p>

            <div class="subsection-title">1.2 Primary Objectives</div>
            <table class="mb-20 avoid-break-inside">
                <tr>
                    <th width="40%">Objective</th>
                    <th>Description</th>
                </tr>
                <tr>
                    <td><strong>Identification & Assessment</strong></td>
                    <td>{{ identification_objective }}</td>
                </tr>
                <tr>
                    <td><strong>Remediation & Validation</strong></td>
                    <td>{{ remediation_objective }}</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Page 5: Executive Summary - Project Details -->
    <div class="pdf-page">
        <div class="section">
            <div class="section-title">1. EXECUTIVE SUMMARY (CONTINUED)</div>

            <div class="subsection-title">1.3 Project Details</div>
            <table class="mb-20 avoid-break-inside">
                <tr>
                    <th width="40%">Field</th>
                    <th>Details</th>
                </tr>
                <tr>
                    <td>Organization Name</td>
                    <td>{{ organization }}</td>
                </tr>
                <tr>
                    <td>Target URL</td>
                    <td>{{ target_url }}</td>
                </tr>
                <tr>
                    <td>Cyber Security Engineer</td>
                    <td>{{ security_engineer }}</td>
                </tr>
                <tr>
                    <td>Project Type</td>
                    <td>{{ project_type }}</td>
                </tr>
                <tr>
                    <td>Audit Period</td>
                    <td>{{ audit_period }}</td>
                </tr>
                <tr>
                    <td>Assessment Period</td>
                    <td>{{ assessment_period }}</td>
                </tr>
                <tr>
                    <td>Initial Security Grade</td>
                    <td>{{ initial_grade }}</td>
                </tr>
                <tr>
                    <td>Final Security Grade</td>
                    <td>{{ final_grade }}</td>
                </tr>
                <tr>
                    <td>Current Status</td>
                    <td>{{ current_status }}</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Page 6: Scope of Assessment -->
    <div class="pdf-page">
        <div class="section">
            <div class="section-title">2. SCOPE OF ASSESSMENT</div>

            <p class="mb-20">{{ scope_description }}</p>

            <div class="subsection-title">2.1 Assessment Objectives</div>
            <table class="mb-20 avoid-break-inside">
                <tr>
                    <th width="30%">Objective</th>
                    <th>Description</th>
                </tr>
                <tr>
                    <td><strong>Identifying Security Loopholes</strong></td>
                    <td>{{ objective1 }}</td>
                </tr>
                <tr>
                    <td><strong>Posturing Improvements</strong></td>
                    <td>{{ objective2 }}</td>
                </tr>
                <tr>
                    <td><strong>Impact Analysis</strong></td>
                    <td>{{ objective3 }}</td>
                </tr>
                <tr>
                    <td><strong>Actionable Recommendations</strong></td>
                    <td>{{ objective4 }}</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Page 7: Scope of Assessment - Target Assets -->
    <div class="pdf-page">
        <div class="section">
            <div class="section-title">2. SCOPE OF ASSESSMENT (CONTINUED)</div>

            <div class="subsection-title">2.2 Target Assets</div>
            <table class="avoid-break-inside">
                <tr>
                    <th width="40%">Field</th>
                    <th>Details</th>
                </tr>
                <tr>
                    <td>Target Name</td>
                    <td>{{ target_name }}</td>
                </tr>
                <tr>
                    <td>Type</td>
                    <td>{{ asset_type }}</td>
                </tr>
                <tr>
                    <td>Scope URL</td>
                    <td>{{ target_url }}</td>
                </tr>
                <tr>
                    <td>Authentication State</td>
                    <td>{{ authentication_state }}</td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Page 8: Security Scorecard -->
    <div class="pdf-page">
        <div class="section">
            <div class="section-title">3. SECURITY SCORECARD</div>

            <table class="mb-20 avoid-break-inside">
                <tr>
                    <th>Target Asset</th>
                    <th>Initial Grade</th>
                    <th>Final Grade</th>
                    <th>Current Status</th>
                </tr>
                <tr>
                    <td>{{ target_url }}</td>
                    <td>{{ initial_grade }}</td>
                    <td>{{ final_grade }}</td>
                    <td><span class="status-badge">{{ current_status }}</span></td>
                </tr>
            </table>

            <div class="subsection-title">3.1 Vulnerability Distribution</div>
            <table class="mb-20 avoid-break-inside">
                <tr>
                    <th>Vulnerability Name</th>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.finding }}</td>
                    <td><span class="severity-badge {{ vuln.severity|lower }}">{{ vuln.severity }}</span></td>
                    <td><span class="status-badge">{{ vuln.status }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>

    <!-- Page 9: Summary Statistics -->
    <div class="pdf-page">
        <div class="section">
            <div class="section-title">3. SECURITY SCORECARD (CONTINUED)</div>

            <div class="subsection-title">3.2 Summary Statistics</div>
            <table class="avoid-break-inside">
                <tr>
                    <th>Severity Level</th>
                    <th>Count</th>
                    <th>Remediated</th>
                    <th>Remediation Rate</th>
                </tr>
                {% set severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0} %}
                {% set severity_remediated = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0} %}
                {% for vuln in vulnerabilities %}
                    {% set _ = severity_counts.update({vuln.severity: severity_counts[vuln.severity] + 1}) %}
                    {% if vuln.status == 'Solved' %}
                        {% set _ = severity_remediated.update({vuln.severity: severity_remediated[vuln.severity] + 1}) %}
                    {% endif %}
                {% endfor %}

                {% for severity in ['Critical', 'High', 'Medium', 'Low'] %}
                    {% if severity_counts[severity] > 0 %}
                    <tr>
                        <td><span class="severity-badge {{ severity|lower }}">{{ severity }}</span></td>
                        <td>{{ severity_counts[severity] }}</td>
                        <td>{{ severity_remediated[severity] }}</td>
                        <td>{{ ((severity_remediated[severity] / severity_counts[severity]) * 100)|int if severity_counts[severity] > 0 else 0 }}%</td>
                    </tr>
                    {% endif %}
                {% endfor %}
                <tr>
                    <td><strong>Total</strong></td>
                    <td><strong>{{ vulnerabilities|length }}</strong></td>
                    <td><strong>{{ vulnerabilities|selectattr('status', 'equalto', 'Solved')|list|length }}</strong></td>
                    <td><strong>{{ ((vulnerabilities|selectattr('status', 'equalto', 'Solved')|list|length / vulnerabilities|length) * 100)|int if vulnerabilities|length > 0 else 0 }}%</strong></td>
                </tr>
            </table>
        </div>
    </div>

    <!-- Dynamic Pages for Vulnerabilities -->
    {% set severity_index = namespace(value=1) %}
    {% for severity in ['Critical', 'High', 'Medium', 'Low'] %}
        {% set vulns_in_severity = vulnerabilities|selectattr('severity', 'equalto', severity)|list %}
        {% if vulns_in_severity %}
            <!-- Force new page for each severity section -->
            <div class="pdf-page">
                <div class="section">
                    <div class="section-title">4. DETAILED VULNERABILITY FINDINGS</div>

                    <div class="subsection-title" style="color: {% if severity == 'Critical' %}#c00{% elif severity == 'High' %}#ff6f00{% elif severity == 'Medium' %}#ff8f00{% else %}#2e7d32{% endif %};">
                        <span class="severity-badge {{ severity|lower }}">{{ severity }}</span> Severity Findings
                    </div>

                    {% for vuln in vulns_in_severity %}
                    <div class="finding-card keep-together" style="margin-top: {{ '20px' if not loop.first else '0px' }}">
                        <div class="finding-header">
                            <div>
                                <div class="finding-title">{{ vuln.name }}</div>
                                <div>
                                    <span class="severity-badge {{ severity|lower }}">{{ severity }}</span>
                                    <span class="status-badge">{{ vuln.status }}</span>
                                </div>
                            </div>
                            <div class="risk-score risk-{{ severity|lower }}">Risk: {{ vuln.risk_score }}/10</div>
                        </div>
                        <div class="finding-body">
                            <div class="finding-section">
                                <div class="section-label">Description</div>
                                <p>{{ vuln.description }}</p>
                            </div>

                            <div class="finding-section">
                                <div class="section-label">Impact</div>
                                <p>{{ vuln.impact }}</p>
                            </div>

                            <div class="finding-section">
                                <div class="section-label">Proof of Concept</div>
                                {% if vuln.poc is string %}
                                    <div class="proof-box">{{ vuln.poc }}</div>
                                {% else %}
                                    <div class="proof-box">
                                        <ol>
                                            {% for step in vuln.poc %}
                                            <li>{{ step }}</li>
                                            {% endfor %}
                                        </ol>
                                    </div>
                                {% endif %}
                            </div>

                            <div class="finding-section">
                                <div class="section-label">Remediation Status</div>
                                <div class="remediation-box">
                                    <div class="section-label">{{ vuln.status.upper() }}</div>
                                    <p>{{ vuln.remediation }}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% set severity_index.value = severity_index.value + 1 %}
        {% endif %}
    {% endfor %}

    <!-- Conclusion Page -->
    <div class="pdf-page">
        <div class="section mt-30">
            <div class="section-title">5. CONCLUSION</div>

            <div class="subsection-title">Final Assessment Summary</div>
            <p class="mb-20">{{ conclusion }}</p>

            <table class="mb-20 avoid-break-inside">
                <tr>
                    <th width="60%">Key Achievement</th>
                    <th>Result</th>
                </tr>
                <tr>
                    <td>Overall Security Grade Improvement</td>
                    <td><span style="color: #2e7d32; font-weight: bold;">{{ initial_grade }} → {{ final_grade }}</span></td>
                </tr>
                <tr>
                    <td>Critical Vulnerabilities Remediated</td>
                    <td><span style="color: #2e7d32; font-weight: bold;">
                        {{ (vulnerabilities|selectattr('severity', 'equalto', 'Critical')|selectattr('status', 'equalto', 'Solved')|list|length) }}/{{ (vulnerabilities|selectattr('severity', 'equalto', 'Critical')|list|length) }}
                    </span></td>
                </tr>
                <tr>
                    <td>Total Security Controls Implemented</td>
                    <td><span style="color: #2e7d32; font-weight: bold;">{{ vulnerabilities|length }} Controls</span></td>
                </tr>
                <tr>
                    <td>Remediation Completion Rate</td>
                    <td><span style="color: #2e7d32; font-weight: bold;">
                        {{ (vulnerabilities|selectattr('status', 'equalto', 'Solved')|list|length) }}/{{ vulnerabilities|length }} Findings
                    </span></td>
                </tr>
            </table>
        </div>
    </div>
</body>
</html>"""

# Data entry form HTML (updated with CyberWacht branding)
FORM_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberWacht - VAPT Report Generator</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        h1 {
            color: #0d5ec4;
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid #0d5ec4;
            padding-bottom: 15px;
        }
        h2 {
            color: #0d5ec4;
            border-bottom: 2px solid #0d5ec4;
            padding-bottom: 10px;
            margin-top: 30px;
        }
        .form-section {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #333;
        }
        input, textarea, select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        textarea {
            min-height: 100px;
            resize: vertical;
        }
        .form-row {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }
        .form-row > div {
            flex: 1;
        }
        .vuln-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #0d5ec4;
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .btn {
            background: #0d5ec4;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #0a4ba8;
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .btn-success {
            background: #28a745;
        }
        .btn-success:hover {
            background: #218838;
        }
        .btn-group {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            justify-content: center;
        }
        .severity-badge {
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #000; }
        .severity-low { background: #28a745; }
        .logo-preview {
            max-width: 200px;
            max-height: 60px;
            margin-top: 10px;
            border: 1px solid #ddd;
            padding: 5px;
            border-radius: 5px;
        }
        .logo-info {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header img {
            max-height: 60px;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CyberWacht - VAPT Report Generator</h1>
        </div>

        <form method="POST" action="/generate" enctype="multipart/form-data">
            <!-- Logo Upload -->
            <h2>0. Company Logo (Optional)</h2>
            <div class="form-section">
                <label for="logo">Upload Logo (PNG recommended, max 200x60px):</label>
                <input type="file" id="logo" name="logo" accept=".png,.jpg,.jpeg">
                <div class="logo-info">If no logo is uploaded, the report will use a text header.</div>
            </div>

            <!-- Basic Information -->
            <h2>1. Basic Information</h2>
            <div class="form-row">
                <div class="form-section">
                    <label>Organization Name:</label>
                    <input type="text" name="organization" value="CyberWacht" required>
                </div>
                <div class="form-section">
                    <label>Target URL:</label>
                    <input type="text" name="target_url" value="https://cyberwacht.decentralcode.tech" required>
                </div>
            </div>

            <div class="form-row">
                <div class="form-section">
                    <label>Security Engineer:</label>
                    <input type="text" name="security_engineer" value="Security Team" required>
                </div>
                <div class="form-section">
                    <label>Project Type:</label>
                    <input type="text" name="project_type" value="Comparative Vulnerability Assessment" required>
                </div>
            </div>

            <div class="form-row">
                <div class="form-section">
                    <label>Audit Period:</label>
                    <input type="text" name="audit_period" value="{{ current_month }} 2025" required>
                </div>
                <div class="form-section">
                    <label>Assessment Period:</label>
                    <input type="text" name="assessment_period" value="{{ current_month }} 1-28, 2025" required>
                </div>
            </div>

            <!-- Security Grades -->
            <h2>2. Security Assessment</h2>
            <div class="form-row">
                <div class="form-section">
                    <label>Initial Security Grade:</label>
                    <input type="text" name="initial_grade" value="C" required>
                </div>
                <div class="form-section">
                    <label>Final Security Grade:</label>
                    <input type="text" name="final_grade" value="B+" required>
                </div>
                <div class="form-section">
                    <label>Current Status:</label>
                    <input type="text" name="current_status" value="Secure" required>
                </div>
            </div>

            <!-- Project Details -->
            <h2>3. Project Details</h2>
            <div class="form-section">
                <label>Project Overview:</label>
                <textarea name="project_overview" rows="4" required>CyberWacht commissioned a comprehensive security assessment of cyberwacht.decentralcode.tech to evaluate its defensive posture against modern cyber threats. The assessment was conducted using a hybrid methodology that combined automated vulnerability scanning with manual penetration testing. The assessment identified a set of security vulnerabilities of varying severity across both the application and infrastructure layers. All identified findings were successfully addressed and remediated in coordination with the technical team, followed by validation to confirm the effectiveness of the implemented fixes.</textarea>
            </div>

            <div class="form-row">
                <div class="form-section">
                    <label>Identification Objective:</label>
                    <textarea name="identification_objective" rows="3" required>Identify security vulnerabilities in system configurations, application logic, and infrastructure through automated scanning and manual penetration testing, and evaluate their potential impact on data confidentiality and business operations.</textarea>
                </div>
                <div class="form-section">
                    <label>Remediation Objective:</label>
                    <textarea name="remediation_objective" rows="3" required>Remediate all identified vulnerabilities in coordination with the technical team and perform validation testing to ensure that the implemented fixes effectively eliminated or reduced the identified security risks.</textarea>
                </div>
            </div>

            <!-- Scope Information -->
            <h2>4. Scope Information</h2>
            <div class="form-section">
                <label>Scope Description:</label>
                <textarea name="scope_description" rows="3" required>This assessment used a two-part approach to ensure comprehensive security coverage. First, automated scans were performed to quickly check for thousands of known risks. Second, security experts performed manual testing to find complex issues that software might miss. All testing was conducted according to global industry standards (such as OWASP and NIST) to ensure the highest level of accuracy.</textarea>
            </div>

            <div class="form-row">
                <div class="form-section">
                    <label>Target Name:</label>
                    <input type="text" name="target_name" value="CyberWacht Platform" required>
                </div>
                <div class="form-section">
                    <label>Asset Type:</label>
                    <input type="text" name="asset_type" value="Web Application" required>
                </div>
                <div class="form-section">
                    <label>Authentication State:</label>
                    <input type="text" name="authentication_state" value="Tested with authenticated and unauthenticated users" required>
                </div>
            </div>

            <!-- Vulnerabilities -->
            <h2>5. Vulnerability Findings</h2>
            <div id="vulnerabilities">
                <!-- Vulnerabilities will be added here by JavaScript -->
            </div>

            <button type="button" class="btn" onclick="addVulnerability()">+ Add Vulnerability</button>

            <!-- Conclusion -->
            <h2>6. Conclusion</h2>
            <div class="form-section">
                <label>Conclusion:</label>
                <textarea name="conclusion" rows="6" required>The security assessment of CyberWacht platform confirms that the organization has a strong defensive posture. Immediate attention should be given to remediating high-risk findings. Ongoing security measures, such as regular automated vulnerability scanning and periodic manual penetration testing, are essential to maintain resilience against emerging threats. Long-term security initiatives should focus on strategic hardening through the implementation of a Zero Trust architecture and enhancing employee security awareness to further strengthen the organization's overall security posture.</textarea>
            </div>

            <!-- Metadata -->
            <h2>7. Report Metadata</h2>
            <div class="form-row">
                <div class="form-section">
                    <label>Document Version:</label>
                    <input type="text" name="document_version" value="2.0" required>
                </div>
                <div class="form-section">
                    <label>Classification:</label>
                    <input type="text" name="classification" value="Confidential" required>
                </div>
                <div class="form-section">
                    <label>Distribution:</label>
                    <input type="text" name="distribution" value="Internal Use Only" required>
                </div>
            </div>

            <div class="btn-group">
                <button type="submit" class="btn btn-success">Generate PDF Report</button>
                <button type="button" class="btn" onclick="loadSampleData()">Load Sample Data</button>
                <button type="button" class="btn btn-danger" onclick="clearForm()">Clear Form</button>
            </div>
        </form>
    </div>

    <script>
        let vulnCounter = 0;
        const currentMonth = new Date().toLocaleString('default', { month: 'long' });

        // Set current month in form fields
        document.addEventListener('DOMContentLoaded', function() {
            const auditPeriodField = document.querySelector('input[name="audit_period"]');
            const assessmentPeriodField = document.querySelector('input[name="assessment_period"]');
            
            if (auditPeriodField && auditPeriodField.value.includes('{{ current_month }}')) {
                auditPeriodField.value = auditPeriodField.value.replace('{{ current_month }}', currentMonth);
            }
            
            if (assessmentPeriodField && assessmentPeriodField.value.includes('{{ current_month }}')) {
                assessmentPeriodField.value = assessmentPeriodField.value.replace('{{ current_month }}', currentMonth);
            }
            
            // Add default vulnerabilities
            loadSampleData();
        });

        // Sample vulnerabilities data
        const sampleVulnerabilities = [
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "XML-RPC Exposed",
                severity: "Critical",
                finding: "Not Protected",
                description: "The xmlrpc.php interface is active, allowing for 'System Multicall' attacks.",
                impact: "Attackers can bypass login rate limits to brute-force administrative credentials or launch Pingback DDoS attacks.",
                poc: "1. Send a POST request to https://cyberwacht.decentralcode.tech/xmlrpc.php\\n2. Use the system.listMethods payload\\n3. Result: The server returns a complete list of active methods, confirming the vulnerability",
                remediation: "The vulnerability has been successfully remediated. Access to the xmlrpc.php endpoint has been restricted at the server level.",
                risk_score: "9.5",
                status: "Solved"
            },
            {
                name: "Clickjacking (UI Redressing)",
                severity: "High",
                finding: "Not Implemented",
                description: "The application does not return an X-Frame-Options or Content-Security-Policy: frame-ancestors header.",
                impact: "An attacker can embed the site into a malicious page via an iframe and trick authenticated users into performing unintended actions.",
                poc: "1. Host a local HTML file with <iframe src='https://cyberwacht.decentralcode.tech'></iframe>\\n2. Result: The site successfully loads in the frame, confirming it can be hijacked",
                remediation: "The X-Frame-Options header has been successfully implemented at the server level with the value SAMEORIGIN.",
                risk_score: "8.0",
                status: "Solved"
            },
            
            {
                name: "Missing Content Security Policy (CSP)",
                severity: "Medium",
                finding: "Not Implemented",
                description: "No CSP header is present to restrict which scripts and resources are allowed to load.",
                impact: "Increases the risk of Cross-Site Scripting (XSS). If a plugin has a vulnerability, a CSP acts as a final safety net to stop malicious scripts from executing.",
                poc: "1. Inspect network headers in a browser\\n2. Result: No Content-Security-Policy header is found",
                remediation: "A strict CSP has been successfully implemented on the server.",
                risk_score: "7.5",
                status: "In Progress"
            },
            {
                name: "Missing Content Security Policy (CSP)",
                severity: "Medium",
                finding: "Not Implemented",
                description: "No CSP header is present to restrict which scripts and resources are allowed to load.",
                impact: "Increases the risk of Cross-Site Scripting (XSS). If a plugin has a vulnerability, a CSP acts as a final safety net to stop malicious scripts from executing.",
                poc: "1. Inspect network headers in a browser\\n2. Result: No Content-Security-Policy header is found",
                remediation: "A strict CSP has been successfully implemented on the server.",
                risk_score: "7.5",
                status: "In Progress"
            },
            {
                name: "Missing Content Security Policy (CSP)",
                severity: "Medium",
                finding: "Not Implemented",
                description: "No CSP header is present to restrict which scripts and resources are allowed to load.",
                impact: "Increases the risk of Cross-Site Scripting (XSS). If a plugin has a vulnerability, a CSP acts as a final safety net to stop malicious scripts from executing.",
                poc: "1. Inspect network headers in a browser\\n2. Result: No Content-Security-Policy header is found",
                remediation: "A strict CSP has been successfully implemented on the server.",
                risk_score: "7.5",
                status: "In Progress"
            },
            {
                name: "Outdated Software Version",
                severity: "Low",
                finding: "Version Detected",
                description: "The application is running an outdated version of its framework with known security vulnerabilities.",
                impact: "Attackers can exploit known vulnerabilities in the outdated software version.",
                poc: "1. Check response headers and page source\\n2. Result: Outdated version information detected in headers",
                remediation: "Update to the latest stable version of the framework.",
                risk_score: "5.0",
                status: "Open"
            }
        ];

        function addVulnerability(vulnData = null) {
            const container = document.getElementById('vulnerabilities');
            const index = vulnCounter++;

            const vulnDiv = document.createElement('div');
            vulnDiv.className = 'vuln-section';
            vulnDiv.innerHTML = `
                <div class="vuln-header">
                    <h3 style="margin: 0;">Vulnerability #${index + 1}</h3>
                    <button type="button" class="btn btn-danger" onclick="this.parentElement.parentElement.remove()">Remove</button>
                </div>
                <div class="form-row">
                    <div class="form-section">
                        <label>Vulnerability Name:</label>
                        <input type="text" name="vuln_name_${index}" value="${vulnData ? vulnData.name : ''}" required>
                    </div>
                    <div class="form-section">
                        <label>Severity:</label>
                        <select name="vuln_severity_${index}" required>
                            <option value="Critical" ${vulnData && vulnData.severity === 'Critical' ? 'selected' : ''}>Critical</option>
                            <option value="High" ${vulnData && vulnData.severity === 'High' ? 'selected' : ''}>High</option>
                            <option value="Medium" ${vulnData && vulnData.severity === 'Medium' ? 'selected' : ''}>Medium</option>
                            <option value="Low" ${vulnData && vulnData.severity === 'Low' ? 'selected' : ''}>Low</option>
                        </select>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-section">
                        <label>Finding:</label>
                        <input type="text" name="vuln_finding_${index}" value="${vulnData ? vulnData.finding : ''}" required>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-section">
                        <label>Risk Score (0-10):</label>
                        <input type="text" name="vuln_risk_score_${index}" value="${vulnData ? vulnData.risk_score : ''}" required>
                    </div>
                    <div class="form-section">
                        <label>Status:</label>
                        <select name="vuln_status_${index}" required>
                            <option value="Solved" ${vulnData && vulnData.status === 'Solved' ? 'selected' : ''}>Solved</option>
                            <option value="Open" ${vulnData && vulnData.status === 'Open' ? 'selected' : ''}>Open</option>
                            <option value="In Progress" ${vulnData && vulnData.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                            <option value="Risk Accepted" ${vulnData && vulnData.status === 'Risk Accepted' ? 'selected' : ''}>Risk Accepted</option>
                        </select>
                    </div>
                </div>
                <div class="form-section">
                    <label>Description:</label>
                    <textarea name="vuln_description_${index}" rows="2" required>${vulnData ? vulnData.description : ''}</textarea>
                </div>
                <div class="form-section">
                    <label>Impact:</label>
                    <textarea name="vuln_impact_${index}" rows="2" required>${vulnData ? vulnData.impact : ''}</textarea>
                </div>
                <div class="form-section">
                    <label>Proof of Concept (one per line):</label>
                    <textarea name="vuln_poc_${index}" rows="3" required>${vulnData ? vulnData.poc : ''}</textarea>
                </div>
                <div class="form-section">
                    <label>Remediation:</label>
                    <textarea name="vuln_remediation_${index}" rows="2" required>${vulnData ? vulnData.remediation : ''}</textarea>
                </div>
            `;

            container.appendChild(vulnDiv);
        }

        function loadSampleData() {
            // Clear existing vulnerabilities
            document.getElementById('vulnerabilities').innerHTML = '';
            vulnCounter = 0;

            // Add sample vulnerabilities
            sampleVulnerabilities.forEach(vuln => {
                addVulnerability(vuln);
            });

            alert('Sample data loaded! Fill in the rest of the form and click "Generate PDF Report".');
        }

        function clearForm() {
            if (confirm('Are you sure you want to clear all form data?')) {
                document.querySelector('form').reset();
                document.getElementById('vulnerabilities').innerHTML = '';
                vulnCounter = 0;
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Render the data entry form"""
    current_month = datetime.now().strftime("%B")
    form_with_month = FORM_TEMPLATE.replace("{{ current_month }}", current_month)
    return form_with_month


@app.route('/generate', methods=['POST'])
def generate_pdf():
    """Generate PDF from form data"""
    try:
        # Collect form data
        form_data = request.form
        
        # Handle logo upload
        logo_base64 = None
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename != '':
                # Read and encode the logo file
                logo_data = logo_file.read()
                if logo_data:
                    logo_base64 = base64.b64encode(logo_data).decode('utf-8')

        # Parse vulnerabilities
        vulnerabilities = []
        i = 0
        while f'vuln_name_{i}' in form_data:
            vuln = {
                'name': form_data[f'vuln_name_{i}'],
                'severity': form_data[f'vuln_severity_{i}'],
                'finding': form_data[f'vuln_finding_{i}'],
                'description': form_data[f'vuln_description_{i}'],
                'impact': form_data[f'vuln_impact_{i}'],
                'poc': form_data[f'vuln_poc_{i}'].split('\n'),
                'remediation': form_data[f'vuln_remediation_{i}'],
                'risk_score': form_data[f'vuln_risk_score_{i}'],
                'status': form_data[f'vuln_status_{i}']
            }
            vulnerabilities.append(vuln)
            i += 1

        # Prepare template data
        template_data = {
            # Basic info
            'organization': form_data['organization'],
            'target_url': form_data['target_url'],
            'security_engineer': form_data['security_engineer'],
            'project_type': form_data['project_type'],
            'audit_period': form_data['audit_period'],
            'assessment_period': form_data['assessment_period'],

            # Security grades
            'initial_grade': form_data['initial_grade'],
            'final_grade': form_data['final_grade'],
            'current_status': form_data['current_status'],

            # Project details
            'project_overview': form_data['project_overview'],
            'identification_objective': form_data['identification_objective'],
            'remediation_objective': form_data['remediation_objective'],

            # Scope
            'scope_description': form_data['scope_description'],
            'target_name': form_data['target_name'],
            'asset_type': form_data['asset_type'],
            'authentication_state': form_data['authentication_state'],

            # Objectives
            'objective1': "Detecting business logic errors and evaluating the effectiveness of existing security controls.",
            'objective2': "Recommending technical security best practices to improve the overall security of the audited applications.",
            'objective3': "Explaining potential risks such as data exposure, financial loss, or reputational damage.",
            'objective4': "Providing clear steps to address identified vulnerabilities.",

            # Vulnerabilities
            'vulnerabilities': vulnerabilities,

            # Conclusion
            'conclusion': form_data['conclusion'],

            # Metadata
            'document_version': form_data['document_version'],
            'classification': form_data['classification'],
            'distribution': form_data['distribution'],

            # Generated fields
            'report_id': f"CW-{datetime.now().year}-{datetime.now().strftime('%m%d')}-{form_data['organization'].upper().replace(' ', '')}",
            'report_date': datetime.now().strftime("%B %d, %Y"),
            'valid_until': (datetime.now() + timedelta(days=30)).strftime("%B %d, %Y"),
            
            # Logo
            'logo_base64': logo_base64 if logo_base64 else LOGO_BASE64
        }

        # Render HTML with template data
        html_content = render_template_string(HTML_TEMPLATE, **template_data)

        # Configure PDF options
        pdf_options = {
            'page-size': 'A4',
            'margin-top': '2.5cm',
            'margin-right': '2cm',
            'margin-bottom': '2cm',
            'margin-left': '2cm',
            'encoding': 'UTF-8',
            'no-outline': None,
            'enable-local-file-access': None,
            'print-media-type': None,
            'disable-smart-shrinking': None,
        }

        # Generate PDF
        temp_file = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
        pdfkit.from_string(html_content, temp_file.name, options=pdf_options)

        # Send PDF as response
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"CyberWacht_VAPT_Report_{form_data['organization']}_{datetime.now().strftime('%Y%m%d')}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        return f"Error generating PDF: {str(e)}<br><br>Details:<br><pre>{error_details}</pre>", 500


if __name__ == '__main__':
    print("Starting CyberWacht VAPT Report Generator...")
    print("Access the web interface at: http://localhost:5000")
    print("\nMake sure you have installed:")
    print("1. pip install flask pdfkit jinja2")
    print("2. Install wkhtmltopdf")
    print("   - Ubuntu/Debian: sudo apt-get install wkhtmltopdf")
    print("   - Windows: Download from https://wkhtmltopdf.org/downloads.html")
    print("   - macOS: brew install wkhtmltopdf")
    print("\nNote: Place your logo.png file in the same directory as this script")
    print("      or upload it through the web interface.")
    print("\nChanges made:")
    print("- Removed blue background from first page")
    print("- Added 'CyberWacht' and 'SECURITY AUDIT REPORT' lines prominently")
    print("- Moved target URL down slightly")
    print("- Removed 'B+ improved from Grade C' box")
    print("- Added proper page separation for all sections")
    print("- TABLE OF CONTENTS is on separate page")
    print("- DOCUMENT INFORMATION is on separate page")
    print("- EXECUTIVE SUMMARY sections are on separate pages")
    print("- SECURITY SCORECARD and Vulnerability Distribution are on separate pages")
    print("- Summary Statistics are on separate page")

    app.run(debug=True, port=5000
    )
