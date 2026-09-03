from flask import Flask, request, redirect, send_file
import sqlite3
import nmap
import ipaddress
import subprocess
import sys
import os

app = Flask(__name__)


def get_data():

    conn = sqlite3.connect("security_scan.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk = 'HIGH'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk = 'MEDIUM'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk = 'LOW'")
    low = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ip, port, service, version, risk, scan_time
        FROM scans
        ORDER BY id DESC
    """)

    results = cursor.fetchall()

    cursor.execute("""
        SELECT ip, port, service, severity,
               finding, recommendation, scan_time
        FROM vulnerabilities
        ORDER BY id DESC
        LIMIT 50
    """)

    vulnerabilities = cursor.fetchall()

    cursor.execute("""
        SELECT
            scan_time,
            ip,
            COUNT(*) AS open_ports,
            SUM(CASE WHEN risk = 'HIGH' THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk = 'MEDIUM' THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk = 'LOW' THEN 1 ELSE 0 END)
        FROM scans
        GROUP BY scan_time, ip
        ORDER BY scan_time DESC
    """)

    history = cursor.fetchall()

    conn.close()

    return (
        total,
        high,
        medium,
        low,
        results,
        vulnerabilities,
        history
    )


@app.route("/")
def dashboard():

    (
        total,
        high,
        medium,
        low,
        results,
        vulnerabilities,
        history
    ) = get_data()


    rows = ""

    for ip, port, service, version, risk, scan_time in results:

        rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{port}</td>
            <td>{service}</td>
            <td>{version}</td>
            <td>
                <b class="risk-{risk.lower()}">
                    {risk}
                </b>
            </td>
            <td>{scan_time}</td>
        </tr>
        """


    alert_rows = ""

    for (
        ip,
        port,
        service,
        severity,
        finding,
        recommendation,
        scan_time
    ) in vulnerabilities:

        alert_rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{port}</td>
            <td>{service}</td>

            <td>
                <b class="severity-{severity.lower()}">
                    {severity}
                </b>
            </td>

            <td>{finding}</td>
            <td>{recommendation}</td>
            <td>{scan_time}</td>
        </tr>
        """


    history_rows = ""

    for (
        scan_time,
        ip,
        open_ports,
        high_count,
        medium_count,
        low_count
    ) in history:

        history_rows += f"""
        <tr>
            <td>{scan_time}</td>
            <td>{ip}</td>
            <td>{open_ports}</td>
            <td class="risk-high">{high_count}</td>
            <td class="risk-medium">{medium_count}</td>
            <td class="risk-low">{low_count}</td>
        </tr>
        """


    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>Network Security Dashboard</title>

        <style>

            body {{
                margin: 0;
                font-family: Arial;
                background: #f4f6f8;
            }}

            .header {{
                background: #111827;
                color: white;
                padding: 25px;
                text-align: center;
            }}

            .container {{
                width: 92%;
                margin: 30px auto;
            }}

            .scan {{
                background: white;
                padding: 20px;
                border-radius: 12px;
                margin-bottom: 25px;
            }}

            input {{
                padding: 12px;
                width: 250px;
                border: 1px solid #ccc;
                border-radius: 6px;
            }}

            button {{
                padding: 12px 20px;
                background: #111827;
                color: white;
                border: none;
                cursor: pointer;
                border-radius: 6px;
                margin-left: 8px;
            }}

            button:hover {{
                background: #374151;
            }}

            .report-button {{
                background: #2563eb;
            }}

            .report-button:hover {{
                background: #1d4ed8;
            }}

            .cards {{
                display: flex;
                gap: 20px;
                flex-wrap: wrap;
            }}

            .card {{
                background: white;
                padding: 25px;
                border-radius: 12px;
                flex: 1;
                min-width: 150px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            }}

            .card h2 {{
                margin: 0;
                font-size: 30px;
            }}

            .table-box {{
                background: white;
                margin-top: 30px;
                padding: 20px;
                border-radius: 12px;
                overflow-x: auto;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            th, td {{
                padding: 14px;
                border-bottom: 1px solid #ddd;
                text-align: left;
                white-space: nowrap;
            }}

            th {{
                background: #f3f4f6;
            }}

            .risk-high,
            .severity-high {{
                color: #dc2626;
            }}

            .risk-medium,
            .severity-medium {{
                color: #d97706;
            }}

            .risk-low {{
                color: #16a34a;
            }}

            .severity-info {{
                color: #2563eb;
            }}

            .severity-review {{
                color: #7c3aed;
            }}

            .history {{
                border-left: 5px solid #111827;
            }}

        </style>

    </head>


    <body>


        <div class="header">

            <h1>🛡 Network Security Dashboard</h1>

            <p>Local Network Security Monitoring</p>

        </div>


        <div class="container">


            <!-- SCAN -->

            <div class="scan">

                <h2>Run Security Scan</h2>

                <form action="/scan" method="POST">

                    <input
                        type="text"
                        name="target"
                        placeholder="192.168.1.1"
                        required
                    >

                    <button type="submit">
                        Run Scan
                    </button>

                    <a href="/report">
                        <button
                            type="button"
                            class="report-button"
                        >
                            📄 Generate Security Report
                        </button>
                    </a>

                </form>

            </div>


            <!-- CARDS -->

            <div class="cards">

                <div class="card">
                    <h2>{total}</h2>
                    <p>Total Open Ports</p>
                </div>

                <div class="card">
                    <h2>{high}</h2>
                    <p>High Risk</p>
                </div>

                <div class="card">
                    <h2>{medium}</h2>
                    <p>Medium Risk</p>
                </div>

                <div class="card">
                    <h2>{low}</h2>
                    <p>Low Risk</p>
                </div>

            </div>


            <!-- SCAN HISTORY -->

            <div class="table-box history">

                <h2>🕒 Scan History</h2>

                <table>

                    <tr>
                        <th>Scan Time</th>
                        <th>IP Address</th>
                        <th>Open Ports</th>
                        <th>High Risk</th>
                        <th>Medium Risk</th>
                        <th>Low Risk</th>
                    </tr>

                    {history_rows}

                </table>

            </div>


            <!-- SECURITY ALERTS -->

            <div class="table-box">

                <h2>🚨 Security Alerts</h2>

                <table>

                    <tr>
                        <th>IP</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>Recommendation</th>
                        <th>Scan Time</th>
                    </tr>

                    {alert_rows}

                </table>

            </div>


            <!-- SCAN RESULTS -->

            <div class="table-box">

                <h2>🔍 Security Scan Results</h2>

                <table>

                    <tr>
                        <th>IP</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Risk</th>
                        <th>Scan Time</th>
                    </tr>

                    {rows}

                </table>

            </div>


        </div>


    </body>

    </html>
    """


@app.route("/scan", methods=["POST"])
def run_scan():

    target = request.form["target"].strip()


    try:

        ip = ipaddress.ip_address(target)

        if not ip.is_private:
            return "Only private/local IP addresses are allowed."

    except ValueError:

        return "Invalid IP address."


    scanner = nmap.PortScanner()

    scanner.scan(target, arguments="-sV")


    if target not in scanner.all_hosts():
        return "Host not found."


    conn = sqlite3.connect("security_scan.db")
    cursor = conn.cursor()


    for protocol in scanner[target].all_protocols():

        for port in scanner[target][protocol]:

            service = scanner[target][protocol]

            name = service.get("name", "unknown")
            version = service.get("version", "unknown")
            state = service.get("state", "unknown")


            if state != "open":
                continue


            if port == 23:

                risk = "HIGH"
                severity = "HIGH"
                finding = "Telnet service is exposed."
                recommendation = "Disable Telnet and use SSH instead."


            elif port == 21:

                risk = "MEDIUM"
                severity = "MEDIUM"
                finding = "FTP service is exposed."
                recommendation = "Prefer SFTP/FTPS or disable FTP if not required."


            elif port == 80:

                risk = "MEDIUM"
                severity = "MEDIUM"
                finding = "HTTP service is exposed."
                recommendation = "Use HTTPS where possible."


            elif port == 22:

                risk = "LOW"
                severity = "LOW"
                finding = "SSH service is exposed."
                recommendation = "Use strong authentication and secure SSH configuration."


            elif port == 443:

                risk = "INFO"
                severity = "INFO"
                finding = "HTTPS service detected."
                recommendation = "Keep TLS configuration and certificates up to date."


            else:

                risk = "REVIEW"
                severity = "REVIEW"
                finding = f"Open service detected on port {port}."
                recommendation = "Verify that this service is required and securely configured."


            cursor.execute("""
                INSERT INTO scans
                (ip, port, service, version, risk, scan_time)
                VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """, (
                target,
                port,
                name,
                version,
                risk
            ))


            cursor.execute("""
                INSERT INTO vulnerabilities
                (ip, port, service, severity,
                 finding, recommendation, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """, (
                target,
                port,
                name,
                severity,
                finding,
                recommendation
            ))


    conn.commit()
    conn.close()


    return redirect("/")


@app.route("/report")
def generate_report():

    report_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "security_report.pdf"
    )


    try:

        subprocess.run(
            [sys.executable, "report_generator.py"],
            check=True
        )

    except Exception as error:

        return f"Report generation failed: {error}"


    if not os.path.exists(report_file):

        return "Security report was not created."


    return send_file(
        report_file,
        as_attachment=True,
        download_name="security_report.pdf"
    )


if __name__ == "__main__":

    app.run(debug=True)