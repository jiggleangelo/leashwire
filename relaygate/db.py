import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY,name TEXT,help_text TEXT,policy_json TEXT,rate_card_json TEXT);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,ws TEXT,name TEXT,provider TEXT,provider_ref TEXT,key_hash TEXT,key_salt TEXT,scopes TEXT,status TEXT,cap_daily_usd REAL,cap_monthly_usd REAL,handler_kind TEXT,handler_url TEXT,auto_resume INTEGER DEFAULT 0,sender TEXT);
CREATE TABLE IF NOT EXISTS senders(number_token TEXT PRIMARY KEY,ws TEXT,agent_id TEXT,provider TEXT,keyword_mode TEXT CHECK(keyword_mode IN ('relaygate','provider')),is_toll_free INTEGER);
CREATE TABLE IF NOT EXISTS consent(id INTEGER PRIMARY KEY,ws TEXT,rcpt TEXT,action TEXT CHECK(action IN('grant','revoke')),source TEXT,evidence_ref TEXT,agent_id TEXT,channel TEXT,ts TEXT);
CREATE INDEX IF NOT EXISTS consent_ws_rcpt ON consent(ws,rcpt,id);
CREATE TABLE IF NOT EXISTS inbound_seen(ws TEXT,rcpt TEXT,last_ts TEXT,PRIMARY KEY(ws,rcpt));
CREATE TABLE IF NOT EXISTS inbound_events(provider TEXT,event_id TEXT,ts TEXT,PRIMARY KEY(provider,event_id));
CREATE TABLE IF NOT EXISTS sends(id INTEGER PRIMARY KEY,agent_id TEXT,rcpt TEXT,provider_msg_id TEXT,segments INTEGER,est_usd REAL,actual_usd REAL,status TEXT,idem_key TEXT,ts TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS sends_agent_idem ON sends(agent_id,idem_key) WHERE idem_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS sends_provider_msg ON sends(agent_id,provider_msg_id);
CREATE TABLE IF NOT EXISTS voice_usage(agent_id TEXT,day TEXT,usd REAL,PRIMARY KEY(agent_id,day));
CREATE TABLE IF NOT EXISTS compliance_replies(ws TEXT,rcpt TEXT,keyword TEXT,ts TEXT);
CREATE TABLE IF NOT EXISTS route_retries(id INTEGER PRIMARY KEY,agent_id TEXT,event_json TEXT,attempts INTEGER,next_ts TEXT,last_error TEXT);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY,ts TEXT,row_json TEXT,prev_hash TEXT,hash TEXT);
CREATE TABLE IF NOT EXISTS provider_optout_codes(provider TEXT,code TEXT,PRIMARY KEY(provider,code));
"""

def connect(path=":memory:"):
    db=sqlite3.connect(path,check_same_thread=False,timeout=30)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=30000")
    db.executescript(SCHEMA)
    db.commit()
    return db
