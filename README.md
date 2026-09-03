# 🛡 Network Security Scanner & Monitoring Dashboard

A Python-based network security monitoring tool that uses Nmap to discover
open ports and services, performs rule-based security checks, stores scan
results in SQLite, and provides a web dashboard with security alerts,
scan history, and PDF reporting.

## Features

- Network device discovery
- Nmap port scanning
- Service and version detection
- Rule-based security risk assessment
- Vulnerability/security findings
- SQLite database storage
- Scan history
- Security alerts
- Web-based dashboard
- PDF security reports
- Local/private IP validation

## Technologies

- Python
- Nmap
- python-nmap
- Flask
- SQLite
- ReportLab
- HTML/CSS

## Project Workflow

Network
   ↓
Nmap Scan
   ↓
Service Detection
   ↓
Security Analysis
   ↓
Risk Classification
   ↓
SQLite Database
   ↓
Web Dashboard
   ↓
Security Report (PDF)

## How to Run

Install dependencies:

```bash
py -m pip install python-nmap flask reportlab

## Author

**Ayman Mandlekar**

Cybersecurity Enthusiast | Python | Network Security