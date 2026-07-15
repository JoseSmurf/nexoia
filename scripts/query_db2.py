import sqlite3
import json

DB_PATH = r"C:\Users\smurf\.local\share\mimocode\mimocode.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Find real user sessions (not checkpoint-writer) with substantial messages
cur.execute("""
    SELECT s.id, s.title, s.time_created, s.project_id,
           (SELECT COUNT(*) FROM message m WHERE m.session_id = s.id) as msg_count
    FROM session s
    WHERE s.project_id = 'b424c638-fde9-423c-80f4-6fd6ac85a206'
      AND s.title NOT LIKE 'checkpoint-writer:%'
    ORDER BY s.time_created DESC
    LIMIT 30
""")
print("=== REAL SESSIONS (non-checkpoint) ===")
for row in cur.fetchall():
    print(f"  {row[0]} | msgs={row[3]} | {row[1][:60]}")

# Search for user statements with key patterns
print("\n=== USER DIRECTIVES (keywords) ===")
cur.execute("""
    SELECT m.session_id, 
           json_extract(m.data, '$.role') as role,
           json_extract(p.data, '$.text') as text
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE m.session_id IN (
        SELECT id FROM session 
        WHERE project_id = 'b424c638-fde9-423c-80f4-6fd6ac85a206'
          AND title NOT LIKE 'checkpoint-writer:%'
    )
    AND json_extract(m.data, '$.role') = 'user'
    AND json_extract(p.data, '$.type') = 'text'
    AND (
        json_extract(p.data, '$.text') LIKE '%sempre%'
        OR json_extract(p.data, '$.text') LIKE '%nunca%'
        OR json_extract(p.data, '$.text') LIKE '%lembra%'
        OR json_extract(p.data, '$.text') LIKE '%regra%'
        OR json_extract(p.data, '$.text') LIKE '%decid%'
        OR json_extract(p.data, '$.text') LIKE '%commit%'
        OR json_extract(p.data, '$.text') LIKE '%fix%'
        OR json_extract(p.data, '$.text') LIKE '%mudar%'
    )
    ORDER BY m.time_created DESC
    LIMIT 30
""")
for row in cur.fetchall():
    text = row[2] or ""
    if len(text) > 200:
        text = text[:200] + "..."
    print(f"  [{row[0][:20]}] {text}")

# Search for errors in assistant messages
print("\n=== ERRORS IN TRAJECTORY ===")
cur.execute("""
    SELECT m.session_id, json_extract(p.data, '$.text') as text
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE m.session_id IN (
        SELECT id FROM session 
        WHERE project_id = 'b424c638-fde9-423c-80f4-6fd6ac85a206'
          AND title NOT LIKE 'checkpoint-writer:%'
    )
    AND json_extract(p.data, '$.type') = 'text'
    AND json_extract(m.data, '$.role') = 'assistant'
    AND (
        json_extract(p.data, '$.text') LIKE '%error%'
        OR json_extract(p.data, '$.text') LIKE '%Error%'
        OR json_extract(p.data, '$.text') LIKE '%FAILED%'
    )
    ORDER BY m.time_created DESC
    LIMIT 15
""")
for row in cur.fetchall():
    text = row[1] or ""
    if len(text) > 200:
        text = text[:200] + "..."
    print(f"  [{row[0][:20]}] {text}")

conn.close()
