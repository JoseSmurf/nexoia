import sqlite3
import json

DB_PATH = r"C:\Users\smurf\.local\share\mimocode\mimocode.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Find user messages with important directives (broader search)
print("=== USER DIRECTIVES (broader search) ===")
cur.execute("""
    SELECT m.session_id, json_extract(p.data, '$.text') as text, m.time_created
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
        OR json_extract(p.data, '$.text') LIKE '%commit%'
        OR json_extract(p.data, '$.text') LIKE '%format%'
        OR json_extract(p.data, '$.text') LIKE '%test%'
        OR json_extract(p.data, '$.text') LIKE '%clippy%'
        OR json_extract(p.data, '$.text') LIKE '%cargo%'
        OR json_extract(p.data, '$.text') LIKE '%LGPD%'
        OR json_extract(p.data, '$.text') LIKE '%pipeline%'
        OR json_extract(p.data, '$.text') LIKE '%integr%'
        OR json_extract(p.data, '$.text') LIKE '%endpoint%'
        OR json_extract(p.data, '$.text') LIKE '%api%'
    )
    ORDER BY m.time_created DESC
    LIMIT 40
""")
for row in cur.fetchall():
    text = row[1] or ""
    if len(text) > 250:
        text = text[:250] + "..."
    print(f"  [{row[0][:20]}] {text}")

# Check for any user messages that establish project rules
print("\n=== RULE-LIKE USER MESSAGES ===")
cur.execute("""
    SELECT m.session_id, json_extract(p.data, '$.text') as text, m.time_created
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
        json_extract(p.data, '$.text') LIKE '%obrigat%'
        OR json_extract(p.data, '$.text') LIKE '%deve%'
        OR json_extract(p.data, '$.text') LIKE '%proib%'
        OR json_extract(p.data, '$.text') LIKE '%não pode%'
        OR json_extract(p.data, '$.text') LIKE '%jamais%'
        OR json_extract(p.data, '$.text') LIKE '%sempre deve%'
        OR json_extract(p.data, '$.text') LIKE '%regra%'
    )
    ORDER BY m.time_created DESC
    LIMIT 20
""")
for row in cur.fetchall():
    text = row[1] or ""
    if len(text) > 250:
        text = text[:250] + "..."
    print(f"  [{row[0][:20]}] {text}")

# Check actor_registry for subagent usage patterns
print("\n=== SUBAGENT HISTORY (last 10) ===")
cur.execute("""
    SELECT agent_id, session_id, time_created, data
    FROM actor_registry
    ORDER BY time_created DESC
    LIMIT 10
""")
for row in cur.fetchall():
    print(f"  [{row[0][:30]}] session={row[1][:20]} time={row[2]}")

# Check tasks
print("\n=== TASKS (last 20) ===")
cur.execute("""
    SELECT id, session_id, summary, status, time_created
    FROM task
    ORDER BY time_created DESC
    LIMIT 20
""")
for row in cur.fetchall():
    print(f"  {row[0][:20]} | {row[2][:60]} | status={row[3]}")

conn.close()
