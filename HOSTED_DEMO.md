# Hosted demo admission controls

Run the fake browser demo with `python demo.py`. Delivery, provisioning and routing remain in-memory fakes. No live provider is contacted.

A direct client IP can own at most eight of the 64 sandboxes. Pending initialization and pending disposal count toward both limits. Sandboxes expire after ten minutes; requests do not refresh that deadline. Existing cookies retain access when the creation quota is full. A busy sandbox rejects overlapping operations without waiting. Different sandboxes initialize and execute independently; the session registry lock only protects bookkeeping. Expiration and shutdown defer disposal until an active operation finishes.

Direct connections are limited to two workers per peer IP, with 16 workers overall and a 15-second total connection deadline. Three slow peers can occupy at most six workers. Connections rejected by worker admission do not consume the global request budget. Accepted connections retain the global 240/minute limit and direct peers retain their 60/minute limit. These bounds mitigate small-source exhaustion; they do not guarantee availability against distributed flooding.

## Reverse proxy deployment

Set `RELAYGATE_DEMO_TRUSTED_PROXIES` to a comma-separated list of the actual proxy IP addresses or narrow CIDRs, for example `192.0.2.10/32`. The Python factory also accepts `trusted_proxies=("192.0.2.10/32",)`.

Only explicitly trusted proxy peers may supply `X-Real-IP`. The proxy must overwrite that header with the validated visitor address, not append a value supplied by the browser. A missing, duplicate, malformed or multi-address header from a trusted proxy is rejected. Forwarded headers from every other peer are ignored. Trusted traffic uses the validated visitor address for request budgets and session quotas, avoiding a shared 60/minute proxy budget.

The trusted proxy must buffer complete request headers and bodies before opening an upstream request, enforce header/body deadlines and the 64 KB body limit, limit concurrent requests per visitor to two, and buffer upstream responses. Restrict origin access to that proxy when deployed in this mode. Trusted proxy connections bypass the two-connection peer limit because they represent multiple visitors; slow-client protection at this boundary depends on those proxy controls. Do not trust broad public networks or enable this mode for an unbuffered proxy.

Unexpected GET failures return a generic error page. The server suppresses socketserver error tracebacks, including client addresses, for failures during request parsing, processing or response writes.

Regression coverage is in `tests/test_hosted_demo_security.py`, alongside the existing tests. It covers quota exhaustion and recovery, concurrent session operations and initialization, capacity reservation, lifecycle cleanup, private error handling, slow-peer admission, worker cleanup, proxy isolation and spoofed forwarding headers.

No commands or tests were executed while preparing this change. Run `python -m unittest discover` in the target environment before deployment.
