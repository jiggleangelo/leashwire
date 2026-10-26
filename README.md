# leashwire

Prototype: leashwire: consent and spend caps for SMS and voice agents

**Try the live demo (made-up data):** https://try-leashwire.manykiln.com/  
**Product page:** https://leashwire.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. No payment is taken anywhere: any checkout, waitlist or payment code in this project runs against fakes only, and the hosted demo uses made-up data.

- Status: prototype; run the 85 automated tests yourself with `python3 -m unittest discover`
- Runs on the Python 3.12 standard library; external services are faked
- Licence: MIT
- Issues and pull requests are not monitored.

---

# Relaygate MVP

Relaygate is a local SMS control plane with scoped keys, workspace-wide consent and suppression, pessimistic spending reservations, verified inbound webhooks, keyword handling, routing, and an HMAC-chained audit trail.

## Runnable fake acceptance demo

Python 3.12, standard library only:

```sh
python -m relaygate demo
python -m unittest discover
python -m unittest tests.test_e2e_demo tests.test_final_review
```

The demo uses in-memory databases, FakeProvider, FakeDispatcher and FakeClock. It exercises scoped keys, missing-consent rejection, consented delivery, idempotency, cross-provider STOP suppression, HELP, START, provider-managed keywords, cap suspension, all three routing shapes, reconciliation, and audit verification. Tests patch network boundaries. The additional HTTP tests execute handlers in memory without listening sockets.

The existing tests are retained. No commands or tests were executed while preparing these files.

## Local server

```sh
export RELAYGATE_VAULT_KEY='replace-with-at-least-32-random-bytes'
export RELAYGATE_ADMIN_TOKEN='replace-with-a-long-random-admin-token'
export RELAYGATE_PROVIDERS=fake
python -m relaygate init
python -m relaygate serve
```

Open http://127.0.0.1:8787/ and enter the admin token. The dashboard displays agent status, spend, caps and audit verification. Public HTML contains no account data. The token stays in the password field and is not stored in browser storage.

Initialization creates empty databases. Provision workspaces, agents and sender mappings through the Python interfaces before receiving traffic. Embedding applications must hold `app['lock']` around direct database access after startup. Services share a reentrant lock. Request-body reads and response writes run outside that lock.

Use `python -m relaygate poll --once` or `python -m relaygate poll --interval 60` for reconciliation. Fake reconciliation is implemented. Live limitations are listed below.

## Provider selection and live limitations

`RELAYGATE_PROVIDERS` accepts comma-separated `telnyx`, `twilio` and `fake`. Production defaults to `telnyx`; fake operation must be explicitly selected. `build()` remains an in-memory fake builder by default for tests and demonstrations. Configured adapters are registered with the vault and shared by provisioning, sending and reconciliation.

Telnyx requires `TELNYX_API_KEY`. Provisioning requests a disabled messaging profile with `daily_spend_limit` and `daily_spend_limit_enabled`, reads the cap back, and only enables a confirmed profile. Failed verification leaves the profile disabled and prevents local agent creation. Remote suspension disables the profile. These API fields and the reset timezone still require live account validation. Live Telnyx usage reconciliation raises `usage_unavailable` rather than silently claiming zero usage.

Twilio requires `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN`. The adapter no longer returns a fabricated restricted-key reference or sends using the parent account credentials. Provisioning and outbound sends fail closed unless a deployment supplies a scope controller through `RELAYGATE_TWILIO_SCOPE_FACTORY=package.module:create_controller`.

The factory takes no arguments and returns an object implementing:

- `provision_agent_scope(agent_id, daily_cap_usd) -> opaque_ref`: create restricted message credentials and an enforceable provider-side spending backstop.
- `verify_agent_scope(ref, daily_cap_usd) -> bool`: verify both controls before local activation.
- `credentials(ref) -> dict`: return `account_sid`, `key_sid`, and `key_secret` from a deployment-owned secret store, including after restart.
- `disable_agent_scope(ref)`: disable the remote scope.
- `usage(ref, since) -> dict`: return message costs and voice usage in the existing Provider format.

No production Twilio controller is included. A restricted API key or usage alert must not be represented as a hard native spending cap. Consequently the complete live Twilio provisioning requirement remains unresolved; only the explicit controller contract and its fake tests are supplied. This repository should not be described as externally shippable on that basis. Telnyx usage reconciliation and live validation also remain outstanding.

HTTP rejection codes are extracted without retaining provider response bodies. Ambiguous transport failures propagate so the pipeline retains its reservation and idempotency marker. Twilio opt-out code 21610 is installed in the configuration table; Telnyx opt-out codes still require account-specific verification.

## Webhooks and throttling

Configure `TWILIO_AUTH_TOKEN`, `RELAYGATE_TWILIO_WEBHOOK_URL` and/or `TELNYX_PUBLIC_KEY`. The Twilio URL must exactly match the externally visible signed callback URL.

Built applications and `make_server()` do not apply a shared per-IP request budget to webhooks. This prevents reverse-proxy traffic from exhausting STOP capacity. Every webhook still requires a valid provider signature, bounded request size and a total body-read deadline. Forwarded IP headers are not trusted. Configure perimeter capacity controls without sharing the outbound API budget with webhook ingress.

Messages and administrative requests retain bounded throttles. Throttle state has a fixed maximum number of keys, at most `limit` accepted timestamps per key, and expiration of inactive keys. When full, unseen keys are rejected without evicting active budgets. Legacy applications constructing APIHandler directly without the builder retain the original webhook-throttle policy; set `app['unthrottled_webhooks'] = True` when embedding it.

A verified event for an unmapped destination is acknowledged and audited as `inbound.ignored`, without persisting contacts or routing it. Transient processing failures for mapped destinations remain retryable. Invalid signatures are rejected before any ledger change.

## Consent and spending

Ordinary sends fail closed without consent. STOP applies throughout a workspace before replies or routing. Compliance replies bypass consent but reserve spend and deduplicate successful replies per keyword, recipient and rolling 24 hours. Provider-managed keywords do not generate local replies.

Keyword normalization removes trailing punctuation only. It does not join separate words or remove embedded digits. YES, YES!, and yes. all require a recent successful outbound message before granting consent.

The supplied test contract treats 71 emoji as two character-based segments. The public `segments(body)` helper preserves that contract. `segments(body, wire=True)` counts UTF-16 units and returns three for that message. Spend estimation always uses the wire calculation, so satisfying the public helper test does not reduce reservations. GSM extension characters consume two septets in both modes.

Spend windows use UTC. Reservations are serialized. Overshoot is limited by estimate error on in-flight sends plus traffic bypassing Relaygate; an enforceable provider-side backstop must be independently established. Retell/Vapi native provider integrations bypass this gate. Use a custom tool calling `POST /v1/messages`.

## Vault and audit

Contacts are encrypted and authenticated in a separate SQLite vault created with mode 0600. Recipient tokens are deterministic, keyed and workspace-scoped. Consent callers must use the sending agent's workspace when identifying contacts. The vault has no plaintext lookup API; plaintext delivery occurs only through registered egress functions. Forgetting a contact removes its encrypted mapping while preserving suppression and audit history.

The running process holds the encryption key. Encryption protects snapshots, not a compromised process. Sender configuration may contain sender numbers. Fakes retain deliveries in memory for assertions. Recipient numbers and message bodies are not persisted in the application database or audit.

Keys use salted PBKDF2-SHA256 with 100,000 iterations. Audit identifiers have separate validation from free text so opaque identifiers containing decimal runs remain usable. A durable message attempt precedes provider delivery. Pre-delivery audit failure blocks delivery; post-delivery audit failure remains visible without erasing the sent row or idempotency marker. Unknown outcomes retain reservations. Successful routing is not repeated merely because its audit append failed.

The HMAC chain detects tampering; SQLite is not immutable storage. Voice webhook parsing is still outside the implemented SMS handlers. All live-provider behavior requires validation beyond fake acceptance coverage.
