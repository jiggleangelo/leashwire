import hmac
import json
import os
import re
import threading
import time
from collections import OrderedDict, deque
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .audit import AuditUnavailable, log
from .dashboard import HTML, JS
from .inbound import verify_telnyx, verify_twilio
from .vault import InvalidContact

MAX_BODY = 65536


class Throttle:
    def __init__(self, limit=30, window=60, max_keys=4096):
        if limit < 0 or window <= 0 or max_keys <= 0:
            raise ValueError("invalid throttle configuration")
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self.data = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        cutoff = now - self.window
        with self.lock:
            # Entries are ordered by their last accepted timestamp. Rejected
            # requests never extend their lifetime or allocate additional state.
            while self.data:
                oldest, queue = next(iter(self.data.items()))
                if queue[-1] > cutoff:
                    break
                del self.data[oldest]
            if self.limit == 0:
                return False
            queue = self.data.get(key)
            if queue is None:
                if len(self.data) >= self.max_keys:
                    return False
                queue = deque()
                self.data[key] = queue
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(now)
            self.data.move_to_end(key)
            return True


class APIHandler(BaseHTTPRequestHandler):
    app = None
    throttle = Throttle()
    timeout = 10

    def _response(self, status, data, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status, payload):
        self._response(status, json.dumps(payload, separators=(",", ":")).encode(), "application/json")

    def _body(self, raw=False):
        value = self.headers.get("Content-Length")
        if not value or not value.isascii() or not value.isdigit():
            raise ValueError("invalid_length")
        size = int(value)
        if size > MAX_BODY:
            raise OverflowError
        connection = getattr(self, "connection", None)
        deadline = time.monotonic() + self.timeout
        remaining = size
        chunks = []
        read = getattr(self.rfile, "read1", self.rfile.read)
        try:
            while remaining:
                budget = deadline - time.monotonic()
                if budget <= 0:
                    raise TimeoutError("body_timeout")
                if connection is not None:
                    connection.settimeout(budget)
                chunk = read(remaining)
                if not chunk:
                    raise ValueError("incomplete_body")
                chunks.append(chunk)
                remaining -= len(chunk)
            if time.monotonic() >= deadline:
                raise TimeoutError("body_timeout")
        finally:
            if connection is not None:
                connection.settimeout(self.timeout)
        data = b"".join(chunks)
        if raw:
            return data
        body = json.loads(data or b"{}")
        if not isinstance(body, dict):
            raise TypeError("object_required")
        return body

    def _admin(self):
        expected = self.app.get("admin_token", "")
        auth = self.headers.get("Authorization", "")
        if not expected or len(auth) > 512 or not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[7:], expected)

    def _authorize_admin(self):
        if not self.throttle.allow(("admin", self.client_address[0])):
            self.close_connection = True
            self._json(429, {"reason": "rate_limited"})
            return False
        if not self._admin():
            self.close_connection = True
            self._json(401, {"reason": "unauthorized"})
            return False
        return True

    def _allow_public(self, category):
        # Builders enable signature-authenticated webhook ingress without a
        # shared IP budget. A proxy address must not exhaust STOP capacity.
        # Legacy embedding applications may explicitly retain the old policy.
        if category == "webhooks" and self.app.get("unthrottled_webhooks", False):
            return True
        if not self.throttle.allow((category, self.client_address[0])):
            self.close_connection = True
            self._json(429, {"reason": "rate_limited"})
            return False
        return True

    def _workspace(self, workspace):
        return bool(isinstance(workspace, str) and self.app["db"].execute(
            "SELECT 1 FROM workspaces WHERE id=?", (workspace,)).fetchone())

    def do_POST(self):
        self.close_connection = True
        try:
            self._post()
        except TimeoutError:
            self._json(408, {"reason": "request_timeout"})
        except OverflowError:
            self._json(413, {"reason": "payload_too_large"})
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError):
            self._json(400, {"reason": "invalid_request"})
        except (ValueError, InvalidContact):
            self._json(422, {"reason": "invalid_value"})
        except AuditUnavailable:
            self._json(503, {"reason": "audit_unavailable"})
        except Exception as exc:
            log("request failed: " + type(exc).__name__)
            self._json(500, {"reason": "internal_error"})

    def _post(self):
        path = urlparse(self.path).path
        if path.startswith("/webhooks/"):
            if not self._allow_public("webhooks"):
                return
            return self._webhook(path.split("/")[-1])
        if path == "/v1/messages":
            if not self._allow_public("messages"):
                return
            body = self._body()
            key = self.headers.get("Authorization", "")
            key = key[7:] if key.startswith("Bearer ") else ""
            with self.app.get("lock", nullcontext()):
                result = self.app["pipeline"].send(
                    key, body.get("to", ""), body.get("body", ""),
                    idempotency_key=body.get("idempotency_key"))
                status, payload = result.status, result.as_dict()
            return self._json(status, payload)
        if not self._authorize_admin():
            return
        body = self._body()
        with self.app.get("lock", nullcontext()):
            status, payload = self._admin_post(path, body)
        return self._json(status, payload)

    def _admin_post(self, path, body):
        if path in ("/v1/consent/grant", "/v1/consent/revoke"):
            workspace = body.get("workspace")
            if not self._workspace(workspace):
                return 422, {"reason": "unknown_workspace"}
            token = self.app["vault"].identify(body["contact"], workspace)
            agent_id = body.get("agent_id")
            if agent_id and not self.app["db"].execute(
                    "SELECT 1 FROM agents WHERE id=? AND ws=?", (agent_id, workspace)).fetchone():
                return 422, {"reason": "unknown_agent"}
            if path.endswith("grant"):
                cid = self.app["consent"].grant(workspace, token, body["source"], body.get("evidence_ref"), agent_id)
            else:
                cid = self.app["consent"].revoke(workspace, token, body.get("source", "api"), body.get("channel"), agent_id)
            return 201, {"id": cid, "recipient_token": token}
        match = re.fullmatch(r"/v1/agents/([^/]+)/(resume|suspend)", path)
        if match:
            status = "active" if match[2] == "resume" else "suspended_manual"
            self.app["keys"].status(match[1], status)
            return 200, {"status": status}
        return 404, {"reason": "not_found"}

    def _webhook(self, provider):
        if provider not in {"twilio", "telnyx"}:
            return self._json(404, {"reason": "not_found"})
        config = self.app.get("webhooks", {}).get(provider, {})
        if provider == "twilio":
            token = config.get("auth_token", "")
            public_url = config.get("public_url", "")
            if not token or not public_url:
                return self._json(503, {"reason": "webhook_unavailable"})
        elif not config.get("public_key", ""):
            return self._json(503, {"reason": "webhook_unavailable"})
        raw = self._body(raw=True)
        if provider == "twilio":
            params = parse_qs(raw.decode(), keep_blank_values=True)
            flat = {key: value if len(value) > 1 else value[0] for key, value in params.items()}
            if not verify_twilio(public_url, flat, self.headers.get("X-Twilio-Signature", ""), token):
                return self._json(403, {"reason": "invalid_signature"})
            event_id, sender, recipient = flat.get("MessageSid"), flat.get("From"), flat.get("To")
            text = flat.get("Body", "")
        else:
            if not verify_telnyx(raw, self.headers.get("Telnyx-Timestamp", ""),
                                 self.headers.get("Telnyx-Signature-Ed25519", ""), config.get("public_key", "")):
                return self._json(403, {"reason": "invalid_signature"})
            envelope = json.loads(raw).get("data", {})
            payload = envelope.get("payload", {})
            event_id = envelope.get("id")
            sender = (payload.get("from") or {}).get("phone_number")
            targets = payload.get("to") or []
            recipient = (targets[0] or {}).get("phone_number") if targets else None
            text = payload.get("text", "")
        if not all(isinstance(value, str) and value for value in (event_id, sender, recipient)) or not isinstance(text, str):
            return self._json(400, {"reason": "invalid_request"})
        with self.app.get("lock", nullcontext()):
            handled = self.app["inbound"].handle_message(
                provider, sender, recipient, text, event_id=event_id)
        if not handled:
            return self._json(503, {"reason": "inbound_incomplete"})
        return self._json(200, {"ok": True})

    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path == "/":
                return self._response(200, HTML.encode(), "text/html; charset=utf-8")
            if path == "/dashboard.js":
                return self._response(200, JS.encode(), "text/javascript; charset=utf-8")
            if not self._authorize_admin():
                return
            with self.app.get("lock", nullcontext()):
                status, payload = self._admin_get(path)
            self._json(status, payload)
        except Exception as exc:
            log("request failed: " + type(exc).__name__)
            self._json(500, {"reason": "internal_error"})

    def _admin_get(self, path):
        if path == "/v1/audit/verify":
            return 200, {"ok": self.app["audit"].verify_chain()}
        if path == "/v1/audit":
            return 200, {"rows": self.app["audit"].rows()}
        if path == "/v1/agents":
            rows = []
            for agent in self.app["db"].execute("SELECT id,name,provider,status,cap_daily_usd,cap_monthly_usd FROM agents"):
                daily, monthly = self.app["spend"].totals(agent["id"])
                rows.append(dict(agent) | {"spend_daily": daily, "spend_monthly": monthly})
            return 200, {"agents": rows}
        return 404, {"reason": "not_found"}

    def log_message(self, format, *args):
        pass


def make_server(app, host="127.0.0.1", port=8787):
    token = app.get("admin_token") or os.environ.get("RELAYGATE_ADMIN_TOKEN", "")
    if not token:
        raise RuntimeError("RELAYGATE_ADMIN_TOKEN is required")
    app["admin_token"] = token
    app["unthrottled_webhooks"] = True

    class Handler(APIHandler):
        pass

    Handler.app = app
    Handler.throttle = Throttle()
    return ThreadingHTTPServer((host, port), Handler)


def serve(app, host="127.0.0.1", port=8787):
    with make_server(app, host, port) as server:
        server.serve_forever()
