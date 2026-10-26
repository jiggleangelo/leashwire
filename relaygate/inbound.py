import base64
import hashlib
import hmac
import time
from datetime import datetime, timezone, timedelta

from .consent import classify, keyword_word
from .ed25519 import verify as ed_verify


def verify_twilio(url, params, signature, token):
    if not token or not signature:
        return False
    parts = []
    for key in sorted(params):
        value = params[key]
        if isinstance(value, (list, tuple)):
            for item in sorted(str(v) for v in value):
                parts.append(key + item)
        else:
            parts.append(key + str(value))
    expected = base64.b64encode(
        hmac.new(token.encode(), (url + "".join(parts)).encode(), hashlib.sha1).digest()
    ).decode()
    return hmac.compare_digest(expected, signature)


def verify_telnyx(payload, timestamp, signature, public_key, now=None):
    try:
        current = int(now if now is not None else time.time())
        if abs(current - int(timestamp)) > 300:
            return False
        return ed_verify(
            bytes.fromhex(public_key), timestamp.encode() + b"|" + payload,
            base64.b64decode(signature, validate=True),
        )
    except Exception:
        return False


class Inbound:
    def __init__(self, db, vault, consent, pipeline, router, audit, clock=None):
        self.db = db
        self.vault = vault
        self.consent = consent
        self.pipeline = pipeline
        self.router = router
        self.audit = audit
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _mapping(self, to_number):
        candidates = [self.vault.identify(to_number, "")]
        candidates += [self.vault.identify(to_number, row[0]) for row in self.db.execute("SELECT id FROM workspaces")]
        for token in dict.fromkeys(candidates):
            row = self.db.execute("SELECT * FROM senders WHERE number_token=?", (token,)).fetchone()
            if row:
                return row
        return None

    def handle_message(self, provider, from_number, to_number, body, event_id=None):
        mapping = self._mapping(to_number)
        if not mapping:
            # A verified event for an unmanaged destination is permanently ignored.
            # Do not persist contacts, dispatch, or ask the provider to retry it.
            self.audit.append(event="inbound.ignored", provider=provider,
                              decision="ignore", reason="unmapped_sender")
            return True
        event_key = str(event_id) if event_id is not None else None
        if event_key is not None:
            completed = self.db.execute(
                "SELECT 1 FROM inbound_events WHERE provider=? AND event_id=?",
                (provider, event_key),
            ).fetchone()
            if completed:
                return True
        keyword = classify(body)
        rcpt = self.vault.identify(from_number, mapping["ws"])
        event_type = "message.received"
        event_body = body
        if keyword == "stop":
            source = "toll_free_network" if mapping["keyword_mode"] == "provider" and mapping["is_toll_free"] else "inbound_stop"
            self.consent.revoke(mapping["ws"], rcpt, source, "sms", mapping["agent_id"])
            event_type = "consent.revoked"
            event_body = None
        agent = self.db.execute("SELECT * FROM agents WHERE id=?", (mapping["agent_id"],)).fetchone()
        if not agent:
            return False
        rcpt = self.vault.persist(from_number, mapping["ws"])
        self.consent.note_inbound(mapping["ws"], rcpt)
        if keyword == "start":
            is_yes = keyword_word(body) == "YES"
            if not is_yes or self.consent.has_recent_outbound(agent["id"], rcpt):
                self.consent.grant(mapping["ws"], rcpt, "inbound_start", agent_id=agent["id"])
                event_type = "consent.granted"
            else:
                keyword = None
        if keyword in ("stop", "start", "help") and mapping["keyword_mode"] == "relaygate":
            self._reply(agent, rcpt, keyword)
        event = {
            "type": event_type, "workspace": mapping["ws"], "agent_id": agent["id"],
            "recipient_token": rcpt, "keyword": keyword, "provider": provider,
            "received_at": self.clock().isoformat(),
        }
        if event_body is not None:
            event["body"] = event_body
        result = self.router.dispatch(agent, event)
        if not result:
            return result
        if event_key is not None:
            try:
                self.db.execute(
                    "INSERT OR IGNORE INTO inbound_events VALUES(?,?,?)",
                    (provider, event_key, self.clock().isoformat()),
                )
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        return result

    def _reply(self, agent, token, keyword):
        cutoff = (self.clock() - timedelta(hours=24)).isoformat()
        if self.db.execute(
            "SELECT 1 FROM compliance_replies WHERE ws=? AND rcpt=? AND keyword=? AND ts>=?",
            (agent["ws"], token, keyword, cutoff),
        ).fetchone():
            return False
        ws = self.db.execute("SELECT help_text FROM workspaces WHERE id=?", (agent["ws"],)).fetchone()
        text = {
            "stop": "You are unsubscribed. Reply START to opt in.",
            "start": "You are subscribed. Reply STOP to opt out.",
            "help": ws[0],
        }[keyword]
        idem = "compliance:" + token + ":" + keyword + ":" + self.clock().date().isoformat()
        failed = self.db.execute(
            "SELECT id FROM sends WHERE agent_id=? AND idem_key=? AND status='failed'",
            (agent["id"], idem),
        ).fetchone()
        if failed:
            self.db.execute("UPDATE sends SET idem_key=NULL WHERE id=? AND status='failed'", (failed[0],))
            self.db.commit()
        result = self.pipeline.send_internal(agent, token, text, idempotency_key=idem)
        if result.ok:
            self.db.execute(
                "INSERT INTO compliance_replies VALUES(?,?,?,?)",
                (agent["ws"], token, keyword, self.clock().isoformat()),
            )
            self.db.commit()
        return result.ok
