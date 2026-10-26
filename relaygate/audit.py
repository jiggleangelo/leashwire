import hashlib
import hmac
import json
import re
import threading
from datetime import datetime, timezone

ALLOWED = {
    "ts", "workspace", "agent_id", "event", "decision", "reason",
    "recipient_token", "provider", "provider_msg_id", "est_usd",
    "actual_usd", "consent_record_id", "consent_source",
}
PII = re.compile(r"(?:\+[1-9]\d{7,14}|\d{10,}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
RECIPIENT_TOKEN = re.compile(r"rc_[0-9a-f]{32}")
IDENTIFIERS = {
    "agent_id": re.compile(r"ag_[0-9a-f]{12}"),
    "workspace": re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,127}"),
    "provider_msg_id": re.compile(
        r"(?:[A-Za-z][A-Za-z0-9_-]{0,127}|[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    ),
}


def scrub(value):
    return PII.sub("[REDACTED]", str(value))


def log(message, stream=None):
    import sys
    print(scrub(message), file=stream or sys.stderr)


class AuditUnavailable(RuntimeError):
    pass


class Audit:
    def __init__(self, db, clock=None, key=None):
        self.db = db
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.key = key or b"relaygate-ephemeral-audit-key"
        self._lock = threading.RLock()

    def _digest(self, previous, raw):
        return hmac.new(self.key, (previous + raw).encode(), hashlib.sha256).hexdigest()

    def append(self, **fields):
        if set(fields) - ALLOWED:
            raise ValueError("unsupported audit fields")
        fields.setdefault("ts", self.clock().isoformat())
        for name, value in fields.items():
            if value is None:
                continue
            pattern = RECIPIENT_TOKEN if name == "recipient_token" else IDENTIFIERS.get(name)
            if pattern is not None:
                if not isinstance(value, str) or not pattern.fullmatch(value):
                    raise ValueError("invalid audit identifier")
                continue
            if not isinstance(value, (str, int, float, bool)):
                raise ValueError("audit fields must be scalar")
            if isinstance(value, str) and PII.search(value):
                raise ValueError("audit field appears to contain PII")
        raw = json.dumps(fields, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock:
            prev = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            previous = prev[0] if prev else ""
            try:
                cur = self.db.execute(
                    "INSERT INTO audit(ts,row_json,prev_hash,hash) VALUES(?,?,?,?)",
                    (fields["ts"], raw, previous, self._digest(previous, raw)),
                )
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return cur.lastrowid

    def rows(self, limit=100, agent=None):
        limit = max(1, min(int(limit), 1000))
        sql = "SELECT seq,row_json,prev_hash,hash FROM audit"
        args = []
        if agent:
            sql += " WHERE json_extract(row_json,'$.agent_id')=?"
            args.append(agent)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return [dict(row) for row in self.db.execute(sql, args)]

    def verify_chain(self):
        with self._lock:
            previous = ""
            for row in self.db.execute("SELECT row_json,prev_hash,hash FROM audit ORDER BY seq"):
                if row[1] != previous or not hmac.compare_digest(self._digest(previous, row[0]), row[2]):
                    return False
                previous = row[2]
            return True
