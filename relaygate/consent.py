import re
import string
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

STOP = {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT", "OPTOUT", "REVOKE"}
START = {"START", "UNSTOP", "YES"}
HELP = {"HELP", "INFO"}


def keyword_word(body):
    """Normalize trailing punctuation without joining separate words."""
    return str(body).strip().upper().rstrip(string.punctuation)


def classify(body):
    word = keyword_word(body)
    if word in STOP:
        return "stop"
    if word in START:
        return "start"
    if word in HELP:
        return "help"
    return None


@dataclass
class Decision:
    allow: bool
    reason: str
    consent_record_id: int | None = None
    source: str | None = None


class ConsentLedger:
    GRANTS = {"web_form", "import", "api_attested", "inbound_start"}
    REVOKES = {"inbound_stop", "provider_optout_error", "api", "toll_free_network"}

    def __init__(self, db, audit, clock=None, require_explicit=True, conversation_window_h=24):
        self.db = db
        self.audit = audit
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.explicit = require_explicit
        self.window = conversation_window_h

    def _evidence(self, value):
        if value and ("@" in value or re.search(r"\d{7,}", value)):
            raise ValueError("evidence_ref appears to contain PII")

    def grant(self, ws, token, source, evidence_ref=None, agent_id=None):
        if source not in self.GRANTS:
            raise ValueError("invalid consent source")
        self._evidence(evidence_ref)
        cur = self.db.execute(
            "INSERT INTO consent(ws,rcpt,action,source,evidence_ref,agent_id,channel,ts) VALUES(?,?,?,?,?,?,?,?)",
            (ws, token, "grant", source, evidence_ref, agent_id, None, self.clock().isoformat()),
        )
        self.db.commit()
        cid = cur.lastrowid
        self.audit.append(
            workspace=ws, agent_id=agent_id, event="consent.changed", decision="grant",
            reason=source, recipient_token=token, consent_record_id=cid, consent_source=source,
        )
        return cid

    def revoke(self, ws, token, source, channel=None, agent_id=None):
        if source not in self.REVOKES:
            raise ValueError("invalid revoke source")
        cur = self.db.execute(
            "INSERT INTO consent(ws,rcpt,action,source,evidence_ref,agent_id,channel,ts) VALUES(?,?,?,?,?,?,?,?)",
            (ws, token, "revoke", source, None, agent_id, channel, self.clock().isoformat()),
        )
        self.db.commit()
        cid = cur.lastrowid
        self.audit.append(
            workspace=ws, agent_id=agent_id, event="consent.changed", decision="revoke",
            reason=source, recipient_token=token, consent_record_id=cid, consent_source=source,
        )
        return cid

    def note_inbound(self, ws, token):
        self.db.execute(
            "INSERT INTO inbound_seen VALUES(?,?,?) ON CONFLICT(ws,rcpt) DO UPDATE SET last_ts=excluded.last_ts",
            (ws, token, self.clock().isoformat()),
        )
        self.db.commit()

    def has_recent_outbound(self, agent_id, token, hours=24):
        cutoff = (self.clock() - timedelta(hours=hours)).isoformat()
        return bool(self.db.execute(
            "SELECT 1 FROM sends WHERE agent_id=? AND rcpt=? AND status='sent' AND ts>=? LIMIT 1",
            (agent_id, token, cutoff),
        ).fetchone())

    def check(self, ws, token):
        try:
            row = self.db.execute(
                "SELECT id,action,source FROM consent WHERE ws=? AND rcpt=? ORDER BY id DESC LIMIT 1",
                (ws, token),
            ).fetchone()
            if row and row["action"] == "revoke":
                return Decision(False, "suppressed", row["id"], row["source"])
            if row:
                return Decision(True, "consented", row["id"], row["source"])
            if not self.explicit:
                seen = self.db.execute(
                    "SELECT last_ts FROM inbound_seen WHERE ws=? AND rcpt=?", (ws, token),
                ).fetchone()
                if seen and datetime.fromisoformat(seen[0]) >= self.clock() - timedelta(hours=self.window):
                    return Decision(True, "conversation_window")
            return Decision(False, "no_consent")
        except Exception:
            return Decision(False, "ledger_unavailable")
