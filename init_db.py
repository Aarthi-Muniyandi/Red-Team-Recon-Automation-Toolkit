from database import get_db

db = get_db()
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    status TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    module TEXT,
    output TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
)
""")

db.commit()
db.close()

print("[+] Database initialized successfully with status column.")
