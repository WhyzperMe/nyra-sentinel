#!/usr/bin/env python3
"""Offline migration and security contract checks, no Rust claims made."""
import pathlib,sqlite3,hashlib,json,re
root=pathlib.Path(__file__).resolve().parents[1]
conn=sqlite3.connect(':memory:')
conn.execute('PRAGMA foreign_keys=ON')
for m in sorted((root/'migrations').glob('*.sql')):
    conn.executescript(m.read_text())
    print('PASS migration',m.name)
assert {'investigations','harness_tool_audit','detections','security_events','raw_events'} <= set(row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
trace='550e8400-e29b-41d4-a716-446655440000'
conn.execute("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status) VALUES (?,?,?,?)",(trace,'get_ip_history',hashlib.sha256(b'{}').hexdigest(),'ok'))
assert conn.execute('SELECT COUNT(*) FROM harness_tool_audit').fetchone()[0]==1
try:
    conn.execute("INSERT INTO harness_tool_audit(trace_id,tool_name,args_sha256,status) VALUES (?,?,?,?)",(trace,'exec_shell','bad','ok'))
    raise AssertionError('missing hash constraint')
except sqlite3.IntegrityError:
    pass
record=('4c7978dc-309e-4c8d-9618-03410229a721',trace,'ip','203.0.113.7','none','incomplete','Test report','{}','[]',1)
conn.execute("INSERT INTO investigations(id,trace_id,subject_kind,subject_value,model,status,summary,report_json,evidence_json,tool_calls) VALUES (?,?,?,?,?,?,?,?,?,?)",record)
try:
    conn.execute("INSERT INTO investigations(id,trace_id,subject_kind,subject_value,model,status,summary,report_json,evidence_json,tool_calls) VALUES (?,?,?,?,?,?,?,?,?,?)",('other',*record[1:]))
    raise AssertionError('duplicate trace accepted')
except sqlite3.IntegrityError:
    pass
assert conn.execute('SELECT COUNT(*) FROM investigations').fetchone()[0]==1
for path in ('src/harness_api.rs','src/agent/mod.rs','src/agent/client.rs','src/agent/tools.rs'):
    data=(root/path).read_text()
    assert data and len(data)>100
# Parse Rust static SQL snippets from the harness and check SQLite can prepare them.
# This is NOT Rust compilation or executing integration tests.
source=(root/'src/harness_api.rs').read_text()
queries=re.findall(r'sqlx::(?:query|query_scalar)\(\"(.*?)\"\)',source,re.S)
checks=0
for q in queries:
    sql=q.replace('\\\n',' ').replace('\\\r',' ').replace('\\\t',' ')
    if not sql.lstrip().upper().startswith(('SELECT','INSERT')):
        continue
    positions=[int(i) for i in re.findall(r'\?(\d+)',sql)]
    args=[None] * (max(positions) if positions else sql.count('?'))
    try:
        conn.execute('EXPLAIN '+sql, {str(i): value for i, value in enumerate(args, 1)}).fetchall()
    except sqlite3.DatabaseError as e:
        raise AssertionError('invalid harness SQL: '+sql[:100]) from e
    checks+=1
assert checks>=10, checks
assert 'raw_json' not in source[source.index('async fn run('):source.index('async fn audit(')]
print(f'PASS {checks} prepared fixed-SQL harness queries and raw payload isolation')
print('PASS audit/report schema, report idempotency, source contracts')
print('Offline checks only; Rust compilation, Docker and Ollama require host/CI validation.')
