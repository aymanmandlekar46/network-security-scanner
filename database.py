import sqlite3

conn = sqlite3.connect("security_scan.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    service TEXT,
    version TEXT,
    risk TEXT,
    scan_time TEXT
)
""")

conn.commit()
conn.close()

print("Database updated successfully!")