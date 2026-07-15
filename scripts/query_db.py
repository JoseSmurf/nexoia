import sqlite3
import json
import sys

DB_PATH = r"C:\Users\smurf\.local\share\mimocode\mimocode.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# List tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r[0] for r in cur.fetchall()]
print("TABLES:", tables)

# Count rows in each table
for t in tables:
    cur.execute(f"SELECT COUNT(*) FROM [{t}]")
    cnt = cur.fetchone()[0]
    print(f"  {t}: {cnt} rows")

# Show recent sessions
if 'session' in tables:
    print("\n--- RECENT SESSIONS ---")
    cur.execute("SELECT id, project_id, directory, title, time_created FROM session ORDER BY time_created DESC LIMIT 20")
    for row in cur.fetchall():
        print(f"  {row}")

# Show recent messages count per session
if 'message' in tables:
    print("\n--- RECENT MESSAGES (last 20) ---")
    cur.execute("""
        SELECT m.session_id, json_extract(m.data, '$.role') as role, 
               substr(json_extract(m.data, '$.content'), 1, 120) as content_preview,
               m.time_created
        FROM message m 
        ORDER BY m.time_created DESC 
        LIMIT 20
    """)
    for row in cur.fetchall():
        print(f"  [{row[0][:20]}] {row[1]}: {row[2]}  ({row[3]})")

conn.close()
