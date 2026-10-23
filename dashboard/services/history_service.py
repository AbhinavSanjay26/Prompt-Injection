from pathlib import Path
import sqlite3,json
from datetime import datetime,timezone
DB=Path(__file__).resolve().parents[1]/'aths_history.db'
def _conn():
 c=sqlite3.connect(DB); c.execute('CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, created_at TEXT, prompt TEXT, result TEXT)'); c.commit(); return c
def add_history(r):
 try:
  with _conn() as c: c.execute('INSERT INTO scans(created_at,prompt,result) VALUES(?,?,?)',(datetime.now(timezone.utc).isoformat(),r.get('_dashboard_prompt',''),json.dumps({k:v for k,v in r.items() if k!='_dashboard_prompt'},default=str)))
 except Exception: pass
def get_history():
 try:
  with _conn() as c: rows=c.execute('SELECT created_at,prompt,result FROM scans ORDER BY id DESC LIMIT 100').fetchall()
  return [{'timestamp':a,'prompt':b,'result':json.loads(d)} for a,b,d in rows]
 except Exception: return []
def clear_history():
 try:
  with _conn() as c: c.execute('DELETE FROM scans')
 except Exception: pass
