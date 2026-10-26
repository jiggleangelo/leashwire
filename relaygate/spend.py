import json
import math
import sqlite3
import threading
from datetime import datetime, timezone

GSM = set("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")
GSM_EXTENDED = set("^{}\\[~]|€\f")


def segments(body, *, wire=False):
    """Count spec characters by default; wire=True counts UTF-16 code units.

    The public MVP helper preserves the supplied character-count contract.
    All monetary reservations use wire=True, including supplementary Unicode.
    """
    if all(c in GSM or c in GSM_EXTENDED for c in body):
        n = sum(2 if c in GSM_EXTENDED else 1 for c in body)
        single, joined = 160, 153
    else:
        n = len(body.encode("utf-16-be")) // 2 if wire else len(body)
        single, joined = 70, 67
    return 1 if n <= single else math.ceil(n / joined)


class CapExceeded(Exception):
    pass


class Spend:
    def __init__(self, db, providers, audit, clock=None, safety_factor=1.25):
        self.db = db
        self.providers = providers
        self.audit = audit
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.factor = safety_factor
        self._lock = threading.RLock()

    def estimate(self, agent, body, direction="outbound"):
        ws = self.db.execute("SELECT rate_card_json FROM workspaces WHERE id=?", (agent["ws"],)).fetchone()
        rates = json.loads(ws[0] or "{}") if ws else {}
        rate = float(rates.get(agent["provider"], {}).get(direction, .01))
        count = segments(body, wire=True)
        return count, round(count * rate * self.factor, 6)

    def _totals(self, agent_id):
        day = self.clock().date().isoformat()
        month = day[:7]
        totals = []
        for size, window in ((10, day), (7, month)):
            messages = self.db.execute(
                "SELECT COALESCE(SUM(COALESCE(actual_usd,est_usd)),0) FROM sends "
                "WHERE agent_id=? AND substr(ts,1,?)=? AND status IN('reserved','sent')",
                (agent_id, size, window)).fetchone()[0]
            voice = self.db.execute(
                "SELECT COALESCE(SUM(usd),0) FROM voice_usage WHERE agent_id=? AND substr(day,1,?)=?",
                (agent_id, size, window)).fetchone()[0]
            totals.append(float(messages) + float(voice))
        return tuple(totals)

    def totals(self, agent_id):
        with self._lock:
            return self._totals(agent_id)

    def reserve(self, agent, token, count, est, idem=None):
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if idem:
                    old = self.db.execute("SELECT id FROM sends WHERE agent_id=? AND idem_key=?", (agent["id"], idem)).fetchone()
                    if old:
                        self.db.rollback()
                        return -int(old[0])
                daily, monthly = self._totals(agent["id"])
                if daily + est > agent["cap_daily_usd"] or monthly + est > agent["cap_monthly_usd"]:
                    self.db.execute("UPDATE agents SET status='suspended_cap' WHERE id=?", (agent["id"],))
                    self.db.commit()
                    self.audit.append(workspace=agent["ws"], agent_id=agent["id"], event="agent.suspended",
                                      decision="block", reason="cap_exceeded", recipient_token=token,
                                      provider=agent["provider"], est_usd=est)
                    raise CapExceeded
                cur = self.db.execute(
                    "INSERT INTO sends(agent_id,rcpt,segments,est_usd,status,idem_key,ts) VALUES(?,?,?,?,?,?,?)",
                    (agent["id"], token, count, est, "reserved", idem, self.clock().isoformat()))
                self.db.commit()
                return cur.lastrowid
            except (CapExceeded, sqlite3.IntegrityError):
                if self.db.in_transaction:
                    self.db.rollback()
                if idem:
                    old = self.db.execute("SELECT id FROM sends WHERE agent_id=? AND idem_key=?", (agent["id"], idem)).fetchone()
                    if old:
                        return -int(old[0])
                raise
            except Exception:
                self.db.rollback()
                raise

    def bind(self, reservation, msg_id):
        with self._lock:
            self.db.execute("UPDATE sends SET status='sent',provider_msg_id=? WHERE id=?", (msg_id, reservation))
            self.db.commit()

    def release(self, reservation):
        with self._lock:
            self.db.execute("UPDATE sends SET status='failed' WHERE id=?", (reservation,))
            self.db.commit()

    def reconcile_agent(self, agent):
        usage = self.providers[agent["provider"]].usage(agent["provider_ref"], self.clock().date().isoformat())
        with self._lock:
            for item in usage.get("messages", []):
                self.db.execute("UPDATE sends SET actual_usd=? WHERE agent_id=? AND provider_msg_id=?",
                                (item["cost_usd"], agent["id"], item["provider_msg_id"]))
            if usage.get("voice_usd") is not None:
                self.db.execute("INSERT INTO voice_usage VALUES(?,?,?) ON CONFLICT(agent_id,day) DO UPDATE SET usd=excluded.usd",
                                (agent["id"], self.clock().date().isoformat(), float(usage.get("voice_usd", 0))))
            self.db.commit()
            daily, monthly = self._totals(agent["id"])
            over = daily > agent["cap_daily_usd"] or monthly > agent["cap_monthly_usd"]
            if over:
                self.db.execute("UPDATE agents SET status='suspended_cap' WHERE id=?", (agent["id"],))
                self.db.commit()
                self.audit.append(workspace=agent["ws"], agent_id=agent["id"], event="agent.suspended",
                                  decision="block", reason="reconciled_cap", provider=agent["provider"])
                self.providers[agent["provider"]].disable_agent_scope(agent["provider_ref"])
            elif agent["status"] == "suspended_cap" and agent["auto_resume"]:
                self.db.execute("UPDATE agents SET status='active' WHERE id=?", (agent["id"],))
                self.db.commit()
        return daily, monthly

    def poll_once(self):
        for agent in list(self.db.execute("SELECT * FROM agents")):
            self.reconcile_agent(agent)
