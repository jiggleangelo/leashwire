"""Bounded, visitor-isolated hosted demo. All delivery boundaries are fake."""
import html
import hmac
import ipaddress
import json
import os
import secrets
import socket
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from relaygate.cli import build
from relaygate.router import FakeDispatcher
from relaygate.server import APIHandler, Throttle

BANNER = (
    "Demo operated by AI agents. Made-up data. Do not enter real personal data. "
    "Nothing is charged."
)
MAX_BODY = 64 * 1024
MAX_ACTIONS = 32
MAX_SESSIONS = 64
MAX_SESSIONS_PER_IP = 8
SESSION_TTL = 600
MAX_WORKERS = 16
MAX_WORKERS_PER_IP = 2
CONNECTION_DEADLINE = 15
COOKIE = "relaygate_demo"


def escape(value):
    return html.escape(str(value), quote=True)


class DemoState:
    def __init__(self):
        self.lock = threading.RLock()
        self.closed = False
        self._initialize()

    def _initialize(self):
        self.dispatcher = FakeDispatcher()
        self.app = build(key=secrets.token_bytes(32), dispatcher=self.dispatcher)
        self.workspace = "demo"
        self.contact = "+14155550100"
        self.cap_contact = "+14155550199"
        self.sender = "+14155550101"
        self.last_result = "Ready. Try sending before granting consent."
        self.event_number = 0
        self.actions = 0
        self.chain = "verified"
        db = self.app["db"]
        db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?)", (
            self.workspace, "Acme Demo", "Acme Demo support. Reply STOP to opt out.",
            "{}", json.dumps({"fake": {"outbound": .01}}),
        ))
        db.commit()
        self.agent_id, self.agent_key = self.app["keys"].provision_agent(
            self.workspace, "Appointment assistant", "fake", (100, 100),
            handler_kind="langchain", handler_url="demo://appointment-assistant",
            sender="demo-sender-primary",
        )
        self.cap_agent_id, self.cap_agent_key = self.app["keys"].provision_agent(
            self.workspace, "Capped assistant", "fake", (.02, 1),
            handler_kind="vapi", handler_url="demo://capped-assistant",
            sender="demo-sender-capped",
        )
        db.execute("INSERT INTO senders VALUES(?,?,?,?,?,?)", (
            self.app["vault"].identify(self.sender, self.workspace),
            self.workspace, self.agent_id, "fake", "relaygate", 0,
        ))
        db.commit()

    def _dispose(self):
        self.app["db"].close()
        self.app["vault"]._db.close()

    def _event_id(self, action):
        self.event_number += 1
        return "demo-%s-%s" % (action, self.event_number)

    def _cap_test(self):
        db = self.app["db"]
        ref = db.execute("SELECT provider_ref FROM agents WHERE id=?",
                         (self.cap_agent_id,)).fetchone()[0]
        db.execute("DELETE FROM sends WHERE agent_id=?", (self.cap_agent_id,))
        db.execute("UPDATE agents SET status='active' WHERE id=?", (self.cap_agent_id,))
        db.commit()
        provider = self.app["provider"]
        provider.disabled.discard(ref)
        provider.sent[:] = [item for item in provider.sent if item["ref"] != ref]
        token = self.app["vault"].identify(self.cap_contact, self.workspace)
        self.app["consent"].grant(self.workspace, token, "web_form", "cap-demo", self.cap_agent_id)
        results = [self.app["pipeline"].send(
            self.cap_agent_key, self.cap_contact, "Capped demonstration send",
            idempotency_key=self._event_id("cap"),
        ) for _ in range(2)]
        self.last_result = "Cap test: first=%s; second=%s." % tuple(r.reason for r in results)

    def perform(self, action, contact, message):
        with self.lock:
            if action == "reset" or self.actions >= MAX_ACTIONS:
                self._dispose()
                self._initialize()
                if action == "reset":
                    return
            self.actions += 1
            try:
                if action not in {"send", "grant", "stop", "start", "help", "cap"}:
                    raise ValueError("unknown action")
                contact = contact.strip() or self.contact
                if len(contact) > 64:
                    raise ValueError("contact too long")
                message = message[:2000]
                if action == "send":
                    result = self.app["pipeline"].send(
                        self.agent_key, contact,
                        message or "Your made-up appointment is tomorrow at 10:00.",
                        idempotency_key=self._event_id("send"),
                    )
                    self.last_result = "Send result: %s (HTTP %s)." % (result.reason, result.status)
                elif action == "grant":
                    token = self.app["vault"].identify(contact, self.workspace)
                    self.app["consent"].grant(self.workspace, token, "web_form", "demo-form", self.agent_id)
                    self.last_result = "Consent granted from a made-up web form."
                elif action == "cap":
                    self._cap_test()
                else:
                    handled = self.app["inbound"].handle_message(
                        "fake", contact, self.sender, action.upper(), self._event_id(action),
                    )
                    self.last_result = "%s processed and routed: %s." % (action.upper(), "yes" if handled else "no")
            finally:
                self.chain = "verified" if self.app["audit"].verify_chain() else "FAILED"

    def render(self, csrf=""):
        with self.lock:
            token = self.app["vault"].identify(self.contact, self.workspace)
            decision = self.app["consent"].check(self.workspace, token)
            agents = []
            for row in self.app["db"].execute("SELECT id,name,status,cap_daily_usd FROM agents ORDER BY name"):
                daily, _ = self.app["spend"].totals(row["id"])
                agents.append("<tr><td>%s</td><td>%s</td><td>$%.4f / $%.2f</td></tr>" % (
                    escape(row["name"]), escape(row["status"]), daily, row["cap_daily_usd"],
                ))
            deliveries = ["<li><strong>%s</strong> to %s: %s</li>" % (
                escape(item["id"]), escape(item["to"]), escape(item["body"]),
            ) for item in reversed(self.app["provider"].sent[-8:])]
            routes = ["<li><code>%s</code></li>" % escape(json.dumps(payload))
                      for _, payload in reversed(self.dispatcher.calls[-8:])]
            audit = "\n".join(escape(row["row_json"]) for row in self.app["audit"].rows(limit=12))
            buttons = "".join('<button name="action" value="%s">%s</button>' % pair for pair in (
                ("send", "Send through gate"), ("grant", "Grant demo consent"),
                ("stop", "Simulate inbound STOP"), ("help", "Simulate inbound HELP"),
                ("start", "Simulate inbound START"), ("cap", "Run spend-cap test"),
                ("reset", "Reset my demo"),
            ))
            return '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Relaygate user-test demo</title>
<style>body{font:16px system-ui;max-width:980px;margin:auto;padding:1rem;color:#172033;background:#f7f8fb}.banner{background:#fff1b8;border:2px solid #8a6500;padding:1rem;font-weight:bold}section{background:white;padding:1rem;margin:1rem 0}label{display:block;margin:1rem 0}input,textarea{display:block;width:95%%;font:inherit;padding:.5rem}button{font:inherit;margin:.3rem;padding:.5rem}td,th{padding:.5rem;text-align:left}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body>
<div class="banner" role="note">%s</div><h1>Relaygate: try the control plane</h1>
<p>Your browser has a private in-memory database, fake SMS provider and fake handler. Cookies are required.
This sandbox expires after ten minutes and resets before action 33. Reset it at any time below.
The cap experiment starts fresh on every click. These resets are demo behavior only.</p>
<div role="status">%s</div><section><h2>Three-minute core flow</h2>
<ol><li>Send before granting consent.</li><li>Grant consent and send again.</li><li>Simulate STOP and send again.</li><li>Simulate START and send again.</li><li>Run the cap test.</li></ol>
<form method="post" action="/action"><input type="hidden" name="csrf" value="%s">
<label>Made-up recipient<input name="contact" value="%s" maxlength="64" required></label>
<label>Made-up message<textarea name="message" rows="3" maxlength="2000">Your made-up appointment is tomorrow at 10:00.</textarea></label>%s</form></section>
<section><h2>Current gate state</h2><p>Consent decision: <strong>%s</strong> (%s)</p>
<p>Audit chain: <strong>%s</strong> (checked after the latest action)</p>
<table><thead><tr><th>Agent</th><th>Status</th><th>Daily spend / cap</th></tr></thead><tbody>%s</tbody></table></section>
<section><h2>Fake provider deliveries</h2><ul>%s</ul></section>
<section><h2>Fake agent-handler routing</h2><ul>%s</ul></section>
<section><h2>Audit records for this sandbox generation</h2><pre>%s</pre></section></body></html>''' % (
                escape(BANNER), escape(self.last_result), escape(csrf), escape(self.contact), buttons,
                "ALLOW" if decision.allow else "BLOCK", escape(decision.reason), escape(self.chain),
                "".join(agents), "".join(deliveries) or "<li>No fake deliveries yet.</li>",
                "".join(routes) or "<li>No fake handler events yet.</li>", audit or "No audit records yet.",
            )

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                self._dispose()


class SessionUnavailable(Exception):
    pass


class _Session:
    def __init__(self, expires, owner):
        self.expires = expires
        self.owner = owner
        self.state = None
        self.active = True
        self.retired = False


class DemoSessions:
    def __init__(self, maximum=MAX_SESSIONS, ttl=SESSION_TTL, clock=time.monotonic,
                 per_ip=MAX_SESSIONS_PER_IP):
        self.maximum, self.ttl, self.clock = maximum, ttl, clock
        self.per_ip = per_ip
        self.lock = threading.RLock()
        self.sessions = {}
        self.closed = False

    def _dispose(self, token, entry):
        # Retain the capacity reservation until disposal finishes. Never hold
        # the registry lock while initializing, using or closing a database.
        try:
            if entry.state is not None:
                entry.state.close()
        finally:
            with self.lock:
                if self.sessions.get(token) is entry:
                    del self.sessions[token]

    def reap(self):
        dispose = []
        with self.lock:
            now = self.clock()
            for token, entry in self.sessions.items():
                if entry.expires <= now:
                    entry.retired = True
                if entry.retired and not entry.active:
                    entry.active = True
                    dispose.append((token, entry))
        for token, entry in dispose:
            self._dispose(token, entry)

    def run(self, token, create, operation, *, owner=None):
        self.reap()
        with self.lock:
            if self.closed:
                raise SessionUnavailable
            entry = self.sessions.get(token)
            if entry is None:
                if not create or len(self.sessions) >= self.maximum:
                    raise SessionUnavailable
                if owner is not None and sum(e.owner == owner for e in self.sessions.values()) >= self.per_ip:
                    raise SessionUnavailable
                token = secrets.token_urlsafe(32)
                entry = _Session(self.clock() + self.ttl, owner)
                self.sessions[token] = entry
            else:
                # Fail fast for a busy sandbox instead of tying up another
                # worker waiting on the same visitor's operation.
                if entry.active or entry.retired:
                    raise SessionUnavailable
                entry.active = True
        try:
            if entry.state is None:
                try:
                    entry.state = DemoState()
                except BaseException:
                    with self.lock:
                        entry.retired = True
                    raise
            return token, operation(entry.state, token)
        finally:
            with self.lock:
                dispose = entry.retired or self.closed or entry.expires <= self.clock()
                if dispose:
                    entry.retired = True
                else:
                    entry.active = False
            if dispose:
                self._dispose(token, entry)

    def close(self):
        dispose = []
        with self.lock:
            self.closed = True
            for token, entry in self.sessions.items():
                entry.retired = True
                if not entry.active:
                    entry.active = True
                    dispose.append((token, entry))
        for token, entry in dispose:
            self._dispose(token, entry)


class DemoHandler(BaseHTTPRequestHandler):
    timeout = 10
    _body = APIHandler._body

    def setup(self):
        super().setup()
        self.connection.settimeout(self.timeout)

    def _identity(self):
        peer = self.client_address[0]
        if not self.server.is_trusted_proxy(peer):
            return peer
        values = self.headers.get_all("X-Real-IP", [])
        if len(values) != 1 or len(values[0]) > 45:
            raise ValueError("missing or invalid proxy identity")
        return str(ipaddress.ip_address(values[0]))

    def _admit(self):
        try:
            owner = self._identity()
        except ValueError:
            self._error_page(400, "Invalid proxy client identity.")
            return None
        # Direct peers are charged before a worker is allocated. Trusted
        # proxies supply their validated visitor identity after header parsing.
        if self.server.is_trusted_proxy(self.client_address[0]):
            if not self.server.ip_throttle.allow(owner):
                self._error_page(429, "Too many requests. Please try again later.")
                return None
        return owner

    def _token(self):
        raw = self.headers.get("Cookie", "")
        if len(raw) > 4096:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
            return cookie[COOKIE].value if COOKIE in cookie else ""
        except Exception:
            return ""

    def _send(self, status, data, content_type="text/html; charset=utf-8", token=None):
        self.close_connection = True
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if token is not None:
            self.send_header("Set-Cookie", "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%s" % (COOKIE, token, SESSION_TTL))
        self.end_headers()
        self.wfile.write(data)

    def _error_page(self, status, message):
        self._send(status, '<!doctype html><html lang="en"><meta charset="utf-8"><title>Relaygate demo</title><body><div role="note">%s</div><h1>%s</h1><p>%s</p><a href="/">Return to demo</a></body></html>' % (escape(BANNER), status, escape(message)))

    def do_GET(self):
        owner = self._admit()
        if owner is None:
            return
        path = urlparse(self.path).path
        if path == "/healthz":
            return self._send(200, b"ok", "text/plain; charset=utf-8")
        if path != "/":
            return self._error_page(404, "Page not found.")
        try:
            token, page = self.server.demo_state.run(
                self._token(), True, lambda state, token: state.render(token), owner=owner)
        except SessionUnavailable:
            return self._error_page(503, "Demo capacity reached or sandbox busy. Please try again later.")
        except Exception:
            return self._error_page(500, "Demo temporarily unavailable.")
        self._send(200, page, token=token)

    def do_POST(self):
        self.close_connection = True
        if urlparse(self.path).path != "/action":
            return self._error_page(404, "Page not found.")
        value = self.headers.get("Content-Length", "")
        if not value or not value.isascii() or not value.isdigit():
            return self._error_page(411, "A valid Content-Length header is required.")
        if len(value) > 10 or int(value) > MAX_BODY:
            return self._error_page(413, "Request body exceeds 64 KB.")
        try:
            raw = self._body(raw=True)
            values = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=10)
            token = self._token()
            csrf = values.get("csrf", [""])[0]
            if not token or not hmac.compare_digest(token.encode(), csrf.encode()):
                return self._error_page(403, "Open the demo first and submit its form with cookies enabled.")
            if self._admit() is None:
                return
            def perform(state, unused):
                try:
                    state.perform(values.get("action", [""])[0], values.get("contact", [state.contact])[0], values.get("message", [""])[0])
                except (ValueError, KeyError):
                    state.last_result = "Input rejected. Check the form values."
                except Exception:
                    state.last_result = "Demo action failed safely. Reset your demo to retry."
            self.server.demo_state.run(token, False, perform)
        except TimeoutError:
            return self._error_page(408, "Request body deadline exceeded.")
        except OverflowError:
            return self._error_page(413, "Request body exceeds 64 KB.")
        except (ValueError, UnicodeDecodeError):
            return self._error_page(400, "Invalid or incomplete form data.")
        except SessionUnavailable:
            return self._error_page(409, "Your demo expired or is busy. Open the demo again.")
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        pass


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    request_queue_size = MAX_WORKERS
    trusted_proxies = ()

    def __init__(self, address, handler, state, trusted_proxies=()):
        self.demo_state = state
        self.trusted_proxies = tuple(ipaddress.ip_network(value) for value in trusted_proxies)
        self.slots = threading.BoundedSemaphore(MAX_WORKERS)
        self.global_throttle = Throttle(limit=240, max_keys=1)
        self.ip_throttle = Throttle(limit=60, max_keys=512)
        self.peer_lock = threading.Lock()
        self.peer_workers = {}
        super().__init__(address, handler)

    def is_trusted_proxy(self, peer):
        if not self.trusted_proxies:
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(address in network for network in self.trusted_proxies)

    def _reserve_peer(self, peer):
        if self.is_trusted_proxy(peer):
            return True
        with self.peer_lock:
            count = self.peer_workers.get(peer, 0)
            if count >= MAX_WORKERS_PER_IP:
                return False
            self.peer_workers[peer] = count + 1
            return True

    def _release_peer(self, peer):
        if self.is_trusted_proxy(peer):
            return
        with self.peer_lock:
            count = self.peer_workers[peer] - 1
            if count:
                self.peer_workers[peer] = count
            else:
                del self.peer_workers[peer]

    def process_request(self, request, client_address):
        peer = client_address[0]
        # Admission is called serially by serve_forever. Initialize bookkeeping
        # here too for legacy embeddings constructing the server without __init__.
        if not hasattr(self, "peer_lock"):
            self.peer_lock = threading.Lock()
            self.peer_workers = {}
        if not self._reserve_peer(peer):
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self._release_peer(peer)
            self.shutdown_request(request)
            return
        try:
            if not self.is_trusted_proxy(peer) and not self.ip_throttle.allow(peer):
                self.slots.release()
                self._release_peer(peer)
                self.shutdown_request(request)
                return
            if not self.global_throttle.allow("connections"):
                self.slots.release()
                self._release_peer(peer)
                self.shutdown_request(request)
                return
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            self._release_peer(peer)
            raise

    def process_request_thread(self, request, client_address):
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(CONNECTION_DEADLINE, expire)
        timer.daemon = True
        try:
            timer.start()
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            if timer.ident is not None:
                timer.join()
            self.slots.release()
            if hasattr(self, "peer_lock"):
                self._release_peer(client_address[0])

    def handle_error(self, request, client_address):
        # socketserver's default includes the peer address and traceback.
        # Never emit request-specific exception details from this demo.
        pass

    def service_actions(self):
        self.demo_state.reap()

    def server_close(self):
        try:
            super().server_close()
        finally:
            self.demo_state.close()


def build_demo():
    return DemoState()


def make_demo_server(host="0.0.0.0", port=8080, *, trusted_proxies=()):
    sessions = DemoSessions()
    try:
        return DemoServer((host, int(port)), DemoHandler, sessions, trusted_proxies)
    except Exception:
        sessions.close()
        raise


create_server = make_demo_server


def main():
    try:
        port = int(os.environ.get("PORT", "8080"))
    except ValueError as exc:
        raise SystemExit("PORT must be an integer") from exc
    if not 0 <= port <= 65535:
        raise SystemExit("PORT must be between 0 and 65535")
    proxies = tuple(value.strip() for value in os.environ.get("RELAYGATE_DEMO_TRUSTED_PROXIES", "").split(",") if value.strip())
    with make_demo_server("0.0.0.0", port, trusted_proxies=proxies) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
