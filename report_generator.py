import sqlite3
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime


database = "security_scan.db"
output_file = "security_report.pdf"


conn = sqlite3.connect(database)
cursor = conn.cursor()


cursor.execute("""
SELECT ip, port, service, version, risk, scan_time
FROM scans
ORDER BY id DESC
""")

scans = cursor.fetchall()


cursor.execute("""
SELECT ip, port, service, severity, finding, recommendation, scan_time
FROM vulnerabilities
ORDER BY id DESC
LIMIT 50
""")

vulnerabilities = cursor.fetchall()

conn.close()


styles = getSampleStyleSheet()

document = SimpleDocTemplate(
    output_file,
    pagesize=A4,
    rightMargin=30,
    leftMargin=30,
    topMargin=30,
    bottomMargin=30
)

content = []


content.append(
    Paragraph(
        "Network Security Assessment Report",
        styles["Title"]
    )
)

content.append(Spacer(1, 15))

content.append(
    Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    )
)

content.append(Spacer(1, 15))


if scans:
    target_ip = scans[0][0]
else:
    target_ip = "No scan data"


content.append(
    Paragraph(
        f"<b>Target IP:</b> {target_ip}",
        styles["Heading2"]
    )
)

content.append(Spacer(1, 10))


high = sum(1 for v in vulnerabilities if v[3] == "HIGH")
medium = sum(1 for v in vulnerabilities if v[3] == "MEDIUM")
low = sum(1 for v in vulnerabilities if v[3] == "LOW")


content.append(
    Paragraph(
        "Security Summary",
        styles["Heading2"]
    )
)

content.append(
    Paragraph(
        f"High Risk: {high} | Medium Risk: {medium} | Low Risk: {low}",
        styles["Normal"]
    )
)

content.append(Spacer(1, 20))


content.append(
    Paragraph(
        "Detected Services",
        styles["Heading2"]
    )
)


table_data = [
    ["IP", "Port", "Service", "Version", "Risk"]
]


for ip, port, service, version, risk, scan_time in scans[:30]:

    table_data.append([
        ip,
        str(port),
        service,
        version or "unknown",
        risk
    ])


if len(table_data) == 1:

    table_data.append([
        "-", "-", "-", "-", "-"
    ])


table = Table(
    table_data,
    repeatRows=1
)

table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])
)

content.append(table)

content.append(Spacer(1, 20))


content.append(
    Paragraph(
        "Security Findings & Recommendations",
        styles["Heading2"]
    )
)


for ip, port, service, severity, finding, recommendation, scan_time in vulnerabilities[:30]:

    content.append(
        Paragraph(
            f"<b>{severity} - {service} (Port {port})</b>",
            styles["Heading3"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Finding:</b> {finding}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Recommendation:</b> {recommendation}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Detected:</b> {scan_time}",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 10))


content.append(Spacer(1, 15))

content.append(
    Paragraph(
        "<b>Note:</b> This report uses Nmap service detection and "
        "rule-based security checks. It is not a full CVE or penetration-testing report.",
        styles["Normal"]
    )
)


document.build(content)


print(f"\nPDF report created successfully!")
print(f"File: {output_file}")