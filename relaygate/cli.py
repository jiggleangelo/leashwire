import argparse
import hashlib
import importlib
import os
import secrets
import time

from .audit import Audit
from .concurrency import serialize_services
from .consent import ConsentLedger
from .db import connect
from .inbound import Inbound
from .keys import KeyStore
from .pipeline import Pipeline
from .providers.fake import FakeProvider
from .providers.telnyx import TelnyxProvider
from .providers.twilio import TwilioProvider
from .router import Router, HttpDispatcher, FakeDispatcher
from .server import serve
from .spend import Spend
from .vault import LocalVault


def _key(value=None):
    if value is not None:
        return value.encode() if isinstance(value, str) else value
    configured = os.environ.get("RELAYGATE_VAULT_KEY")
    return configured.encode() if configured else secrets.token_bytes(32)


def hmac_key(key):
    return hashlib.sha256(key + b":audit").digest()


def build(db_path=":memory:", vault_path=":memory:", key=None, dispatcher=None, clock=None, providers=None):
    key = _key(key)
    if providers is None:
        providers = {"fake": FakeProvider(cost=.01, drift=1.4)}
    else:
        providers = dict(providers)
    if not providers:
        raise ValueError("at least one provider is required")
    db = connect(db_path)
    try:
        vault = LocalVault(vault_path, key)
    except Exception:
        db.close()
        raise
    for name, provider in providers.items():
        vault.register_egress(name, provider.send)
    audit = Audit(db, clock=clock, key=hmac_key(key))
    keys = KeyStore(db, providers)
    consent = ConsentLedger(db, audit, clock=clock)
    spend = Spend(db, providers, audit, clock=clock)
    pipeline = Pipeline(db, vault, keys, consent, spend, audit, providers)
    router = Router(dispatcher if dispatcher is not None else FakeDispatcher(), audit)
    inbound = Inbound(db, vault, consent, pipeline, router, audit, clock=clock)
    lock = serialize_services((vault, audit, keys, consent, spend, pipeline, router, inbound))
    return {
        "db": db, "provider": next(iter(providers.values())), "providers": providers,
        "vault": vault, "audit": audit, "keys": keys, "consent": consent,
        "spend": spend, "pipeline": pipeline, "router": router, "inbound": inbound,
        "webhooks": {}, "lock": lock, "unthrottled_webhooks": True,
    }


def _scope_controller():
    target = os.environ.get("RELAYGATE_TWILIO_SCOPE_FACTORY", "")
    if not target:
        return None
    module, separator, name = target.partition(":")
    if not separator or not module or not name:
        raise ValueError("RELAYGATE_TWILIO_SCOPE_FACTORY must be module:function")
    return getattr(importlib.import_module(module), name)()


def production_build():
    if not os.environ.get("RELAYGATE_VAULT_KEY"):
        raise RuntimeError("RELAYGATE_VAULT_KEY is required")
    names = {name.strip() for name in os.environ.get("RELAYGATE_PROVIDERS", "telnyx").split(",") if name.strip()}
    if not names or names - {"fake", "telnyx", "twilio"}:
        raise ValueError("RELAYGATE_PROVIDERS contains an unsupported provider")
    providers = {}
    if "fake" in names:
        providers["fake"] = FakeProvider(cost=.01, drift=1.4)
    if "telnyx" in names:
        providers["telnyx"] = TelnyxProvider(os.environ.get("TELNYX_API_KEY", ""))
    if "twilio" in names:
        providers["twilio"] = TwilioProvider(
            os.environ.get("TWILIO_ACCOUNT_SID", ""),
            os.environ.get("TWILIO_AUTH_TOKEN", ""), _scope_controller(),
        )
    app = build(
        os.environ.get("RELAYGATE_DB", "relaygate.db"),
        os.environ.get("RELAYGATE_VAULT_DB", "vault.db"),
        os.environ["RELAYGATE_VAULT_KEY"],
        HttpDispatcher(set(filter(None, os.environ.get("RELAYGATE_HANDLER_ALLOWLIST", "").split(",")))),
        providers=providers,
    )
    app["admin_token"] = os.environ.get("RELAYGATE_ADMIN_TOKEN", "")
    app["webhooks"] = {
        "twilio": {"auth_token": os.environ.get("TWILIO_AUTH_TOKEN", ""), "public_url": os.environ.get("RELAYGATE_TWILIO_WEBHOOK_URL", "")},
        "telnyx": {"public_key": os.environ.get("TELNYX_PUBLIC_KEY", "")},
    }
    if "twilio" in providers:
        app["db"].execute("INSERT OR IGNORE INTO provider_optout_codes VALUES('twilio','21610')")
        app["db"].commit()
    return app


def demo():
    from .demo import run_demo
    app, checks = run_demo()
    try:
        for label, passed in checks.items():
            print(label + ": " + ("OK" if passed else "FAILED"))
        if not all(checks.values()):
            raise RuntimeError("demo acceptance check failed")
    finally:
        app["db"].close()
        app["vault"]._db.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="relaygate")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    sub.add_parser("init")
    srv = sub.add_parser("serve")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8787)
    poll = sub.add_parser("poll")
    poll.add_argument("--interval", type=float, default=60)
    poll.add_argument("--once", action="store_true")
    audit = sub.add_parser("audit")
    audit.add_argument("action", choices=["verify"])
    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return demo()
    if args.cmd == "init":
        if not os.environ.get("RELAYGATE_VAULT_KEY"):
            raise RuntimeError("RELAYGATE_VAULT_KEY is required")
        path = os.environ.get("RELAYGATE_DB", "relaygate.db")
        connect(path).close()
        vault = LocalVault(os.environ.get("RELAYGATE_VAULT_DB", "vault.db"), os.environ["RELAYGATE_VAULT_KEY"])
        vault._db.close()
        print("initialized", path)
        return
    app = production_build()
    try:
        if args.cmd == "serve":
            return serve(app, args.host, args.port)
        if args.cmd == "poll":
            while True:
                app["spend"].poll_once()
                if args.once:
                    return
                time.sleep(max(1, args.interval))
        print("OK" if app["audit"].verify_chain() else "FAILED")
    finally:
        app["db"].close()
        app["vault"]._db.close()
