import sqlite3
DB = "cybercheck.db"

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT, target TEXT, kind TEXT,
            status TEXT, date TEXT DEFAULT CURRENT_TIMESTAMP)""")

def save_scan(analysis_id, target, kind):
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO scans(analysis_id,target,kind,status) VALUES(?,?,?,'pending')",
                  (analysis_id, target, kind))

def update_status(analysis_id, status):
    with sqlite3.connect(DB) as c:
        c.execute("UPDATE scans SET status=? WHERE analysis_id=?", (status, analysis_id))

def history():
    with sqlite3.connect(DB) as c:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC")]

def stats():
    with sqlite3.connect(DB) as c:
        rows = dict(c.execute("SELECT status, COUNT(*) FROM scans GROUP BY status").fetchall())
    return {"total": sum(rows.values()), "safe": rows.get("safe", 0),
            "suspicious": rows.get("suspicious", 0), "danger": rows.get("danger", 0)}