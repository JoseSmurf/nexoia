import sqlite3

DB_PATH = r"C:\Users\smurf\.local\share\mimocode\mimocode.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Find the most recent assistant message mentioning test counts
cur.execute("""
    SELECT m.session_id, json_extract(p.data, '$.text') as text, m.time_created
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE m.session_id IN (
        SELECT id FROM session 
        WHERE project_id = 'b424c638-fde9-423c-80f4-6fd6ac85a206'
          AND title NOT LIKE 'checkpoint-writer:%'
    )
    AND json_extract(m.data, '$.role') = 'assistant'
    AND json_extract(p.data, '$.type') = 'text'
    AND (
        json_extract(p.data, '$.text') LIKE '%test%'
        OR json_extract(p.data, '$.text') LIKE '%passing%'
        OR json_extract(p.data, '$.text') LIKE '%tests%'
    )
    ORDER BY m.time_created DESC
    LIMIT 15
""")
for row in cur.fetchall():
    text = row[1] or ""
    if len(text) > 300:
        text = text[:300] + "..."
    print(f"  [{row[0][:20]}] {text}")

conn.close()
