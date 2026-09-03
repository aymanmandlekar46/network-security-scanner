import nmap
import sqlite3
from datetime import datetime

target = input("Enter your IP address: ")

scanner = nmap.PortScanner()

print("\nScanning and analyzing...\n")

scanner.scan(target, arguments="-sV")

conn = sqlite3.connect("security_scan.db")
cursor = conn.cursor()

scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if target not in scanner.all_hosts():
    print("Host not found.")
else:
    for protocol in scanner[target].all_protocols():

        for port in sorted(scanner[target][protocol]):

            service = scanner[target][protocol][port]

            name = service.get("name", "unknown")
            version = service.get("version", "unknown")
            state = service.get("state", "unknown")

            if state != "open":
                continue

            if port == 23:
                risk = "HIGH"
            elif port == 21:
                risk = "MEDIUM"
            elif port in [22, 80]:
                risk = "LOW"
            elif port == 443:
                risk = "INFO"
            else:
                risk = "REVIEW"

            cursor.execute("""
                INSERT INTO scans
                (ip, port, service, version, risk, scan_time)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                target,
                port,
                name,
                version,
                risk,
                scan_time
            ))

            print(
                f"Port: {port} | "
                f"Service: {name} | "
                f"Version: {version} | "
                f"Risk: {risk}"
            )

conn.commit()
conn.close()

print(f"\nScan saved at: {scan_time}")