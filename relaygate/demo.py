"""Executable acceptance scenario using in-memory stores and fake boundaries."""
import json
from datetime import datetime, timedelta, timezone

from .cli import build
from .providers.fake import FakeProvider
from .router import FakeDispatcher


class FakeClock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, 23, 30, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


def run_demo():
    clock = FakeClock()
    dispatcher = FakeDispatcher()
    app = build(key=b"demo-only-key-not-for-deployment!!", dispatcher=dispatcher, clock=clock)
    app["clock"] = clock
    db = app["db"]
    db.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?)",
        ("acme", "Acme", "Acme support. Reply STOP to opt out.", "{}",
         json.dumps({"fake": {"outbound": .01}, "fake_secondary": {"outbound": .01}})),
    )
    db.execute("INSERT INTO provider_optout_codes VALUES('fake','OPT_OUT')")
    db.commit()
    secondary = FakeProvider()
    app["providers"]["fake_secondary"] = secondary
    app["vault"].register_egress("fake_secondary", secondary.send)

    def provision(name, provider, caps, kind, number=None, mode="relaygate"):
        agent, key = app["keys"].provision_agent(
            "acme", name, provider, caps, handler_kind=kind,
            handler_url="demo://" + name, sender="sender-" + name,
        )
        if number:
            token = app["vault"].identify(number, "acme")
            db.execute("INSERT INTO senders VALUES(?,?,?,?,?,?)",
                       (token, "acme", agent, provider, mode, int(mode == "provider")))
            db.commit()
        return agent, key

    first, key = provision("primary", "fake", (1, 5), "langchain", "+14155550101")
    second, key2 = provision("secondary", "fake_secondary", (1, 5), "mcp", "+18005550102", "provider")
    capped, cap_key = provision("capped", "fake", (.02, 1), "vapi", "+14155550103")
    _, read_key = app["keys"].provision_agent("acme", "reader", "fake", (1, 5), scopes=("events:read",))
    app["demo_agents"] = {"primary": first, "secondary": second, "capped": capped}
    number = "+14155550100"
    token = app["vault"].identify(number, "acme")
    send = app["pipeline"].send
    checks = {}
    checks["scoped key"] = send(read_key, number, "demo denied scope").reason == "wrong_scope"
    checks["no consent"] = send(key, number, "demo denied consent").reason == "no_consent"
    cid = app["consent"].grant("acme", token, "web_form", "form#demo", first)
    initial = send(key, number, "demo private outbound", idempotency_key="demo-initial")
    duplicate = send(key, number, "demo private outbound", idempotency_key="demo-initial")
    checks["consented send and idempotency"] = initial.ok and duplicate.provider_msg_id == initial.provider_msg_id and len(app["provider"].sent) == 1
    checks["second provider send"] = send(key2, number, "demo secondary outbound").ok

    inbound = app["inbound"].handle_message
    checks["STOP processed"] = inbound("fake", number, "+14155550101", "STOP", "demo-stop")
    checks["workspace suppression across providers"] = all(
        send(k, number, "demo suppressed outbound").reason == "suppressed" for k in (key, key2)
    )
    before = len(app["provider"].sent)
    inbound("fake", number, "+14155550101", "STOP", "demo-stop-repeat")
    checks["STOP reply deduplicated"] = len(app["provider"].sent) == before
    inbound("fake", number, "+14155550101", "HELP", "demo-help")
    checks["HELP while suppressed"] = app["provider"].sent[-1]["body"] == "Acme support. Reply STOP to opt out." and not app["consent"].check("acme", token).allow
    inbound("fake", number, "+14155550101", "START", "demo-start")
    checks["START restores consent"] = send(key, number, "demo restored outbound").ok
    inbound("fake", number, "+14155550101", "demo private inbound", "demo-message")

    before = len(secondary.sent)
    inbound("fake_secondary", number, "+18005550102", "STOP", "demo-network-stop")
    network_stop = app["consent"].check("acme", token)
    inbound("fake_secondary", number, "+18005550102", "HELP", "demo-network-help")
    inbound("fake_secondary", number, "+18005550102", "START", "demo-network-start")
    checks["provider managed keywords"] = (
        not network_stop.allow and network_stop.source == "toll_free_network"
        and app["consent"].check("acme", token).allow and len(secondary.sent) == before
    )

    cap_first = send(cap_key, number, "demo cap first")
    before = len(app["provider"].sent)
    cap_block = send(cap_key, number, "demo cap blocked")
    status = db.execute("SELECT status FROM agents WHERE id=?", (capped,)).fetchone()[0]
    checks["spend cap blocks and suspends"] = (
        cap_first.ok and cap_block.reason == "cap_exceeded" and cap_block.status == 402
        and status == "suspended_cap" and len(app["provider"].sent) == before
        and send(cap_key, number, "demo suspended agent").status == 423
    )
    inbound("fake", number, "+14155550103", "demo vapi inbound", "demo-vapi")
    payloads = [payload for _, payload in dispatcher.calls]
    checks["agent routing"] = (
        any(p.get("body") == "demo private inbound" for p in payloads)
        and any(p.get("method") == "notifications/relaygate/event" for p in payloads)
        and any(p.get("data", {}).get("body") == "demo vapi inbound" for p in payloads)
        and any(p.get("type") == "consent.revoked" and "body" not in p for p in payloads)
    )
    app["spend"].poll_once()
    checks["usage reconciliation"] = db.execute("SELECT COUNT(*) FROM sends WHERE status='sent' AND actual_usd IS NULL").fetchone()[0] == 0
    rows = [json.loads(row[0]) for row in db.execute("SELECT row_json FROM audit ORDER BY seq")]
    checks["consent audit linkage"] = any(
        row.get("event") == "message.sent" and row.get("recipient_token") == token
        and row.get("consent_record_id") == cid and row.get("consent_source") == "web_form"
        for row in rows
    )
    checks["audit send block and consent"] = {"message.sent", "message.blocked", "consent.changed", "agent.suspended"}.issubset({row["event"] for row in rows})
    checks["audit chain"] = app["audit"].verify_chain()
    dump = "\n".join(db.iterdump())
    checks["no contacts or message bodies in application DB"] = all(
        value not in dump for value in (
            number, "+14155550101", "+18005550102", "+14155550103",
            "demo private outbound", "demo private inbound", "demo cap first", "demo vapi inbound",
        )
    )
    return app, checks
