from dataclasses import dataclass, asdict

from .audit import AuditUnavailable, log
from .keys import AuthError
from .providers.base import ProviderError, ProviderCapError
from .spend import CapExceeded
from .vault import InvalidContact


@dataclass
class Result:
    ok: bool
    status: int
    reason: str
    recipient_token: str | None = None
    provider_msg_id: str | None = None
    est_usd: float | None = None

    def as_dict(self):
        return asdict(self)


class Pipeline:
    def __init__(self, db, vault, keys, consent, spend, audit, providers):
        self.db = db
        self.vault = vault
        self.keys = keys
        self.consent = consent
        self.spend = spend
        self.audit = audit
        self.providers = providers

    def _append(self, **fields):
        try:
            return self.audit.append(**fields)
        except Exception as exc:
            log("ALERT: audit unavailable; inspect durable reservations before retrying")
            raise AuditUnavailable("audit unavailable") from exc

    def _audit(self, agent, token, event, decision, reason, **extra):
        return self._append(
            workspace=agent["ws"], agent_id=agent["id"], event=event,
            decision=decision, reason=reason, recipient_token=token,
            provider=agent["provider"], **extra,
        )

    def _old(self, agent_id, idem, token=None):
        if not idem:
            return None
        old = self.db.execute(
            "SELECT provider_msg_id,est_usd,status FROM sends WHERE agent_id=? AND idem_key=?",
            (agent_id, idem),
        ).fetchone()
        if not old:
            return None
        if old["status"] == "sent":
            return Result(True, 200, "sent", token, old["provider_msg_id"], old["est_usd"])
        reason = "in_progress" if old["status"] == "reserved" else "previously_failed"
        return Result(False, 409, reason, token, None, old["est_usd"])

    def send(self, api_key, to, body, *, idempotency_key=None):
        try:
            agent = self.keys.authenticate(api_key, "messages:send")
        except AuthError as exc:
            self._append(event="auth.failed", decision="block", reason=exc.reason)
            return Result(False, exc.status, exc.reason)
        try:
            token = self.vault.identify(to, agent["ws"])
        except InvalidContact:
            return Result(False, 422, "invalid_recipient")
        old = self._old(agent["id"], idempotency_key, token)
        if old:
            return old
        decision = self.consent.check(agent["ws"], token)
        if not decision.allow:
            self._audit(agent, token, "message.blocked", "block", decision.reason,
                        consent_record_id=decision.consent_record_id, consent_source=decision.source)
            return Result(False, 409, decision.reason, token)
        self.vault.persist(to, agent["ws"])
        return self._send_agent(agent, token, body, idempotency_key, decision)

    def send_internal(self, agent, token, body, idempotency_key=None, *, reply=True):
        decision = None
        if not reply:
            decision = self.consent.check(agent["ws"], token)
            if not decision.allow:
                self._audit(agent, token, "message.blocked", "block", decision.reason,
                            consent_record_id=decision.consent_record_id, consent_source=decision.source)
                return Result(False, 409, decision.reason, token)
        return self._send_agent(agent, token, body, idempotency_key, decision)

    def _send_agent(self, agent, token, body, idem, decision):
        old = self._old(agent["id"], idem, token)
        if old:
            return old
        count, est = self.spend.estimate(agent, body)
        try:
            reservation = self.spend.reserve(agent, token, count, est, idem)
        except CapExceeded:
            self._audit(agent, token, "message.blocked", "block", "cap_exceeded", est_usd=est)
            return Result(False, 402, "cap_exceeded", token, est_usd=est)
        if reservation < 0:
            return self._old(agent["id"], idem, token)

        # A durable intent is required before any provider side effect.
        try:
            self._audit(agent, token, "message.attempt", "allow", "reserved", est_usd=est)
        except AuditUnavailable:
            self.spend.release(reservation)
            raise
        try:
            sent = self.vault.deliver(token, agent["provider"], sender=agent["sender"],
                                      body=body, ref=agent["provider_ref"])
        except ProviderCapError:
            self.spend.release(reservation)
            self.keys.status(agent["id"], "suspended_cap")
            self._audit(agent, token, "message.failed", "block", "provider_cap", est_usd=est)
            return Result(False, 402, "provider_cap", token, est_usd=est)
        except ProviderError as exc:
            self.spend.release(reservation)
            code = self.db.execute("SELECT 1 FROM provider_optout_codes WHERE provider=? AND code=?",
                                   (agent["provider"], exc.code)).fetchone()
            reason = "provider_error"
            if code:
                self.consent.revoke(agent["ws"], token, "provider_optout_error", agent_id=agent["id"])
                reason = "provider_optout"
            self._audit(agent, token, "message.failed", "block", reason, est_usd=est)
            return Result(False, 502, reason, token, est_usd=est)
        except Exception:
            # Delivery outcome is unknown. Keep the reservation and idempotency
            # marker so a caller cannot accidentally resend an accepted message.
            self._audit(agent, token, "message.failed", "block", "delivery_unknown", est_usd=est)
            return Result(False, 502, "delivery_unknown", token, est_usd=est)

        try:
            self.spend.bind(reservation, sent.provider_msg_id)
        except Exception:
            log("ALERT: delivery persistence failed; reservation requires reconciliation")
            raise
        self._audit(agent, token, "message.sent", "allow", "sent",
                    provider_msg_id=sent.provider_msg_id, est_usd=est,
                    consent_record_id=decision.consent_record_id if decision else None,
                    consent_source=decision.source if decision else None)
        return Result(True, 200, "sent", token, sent.provider_msg_id, est)
