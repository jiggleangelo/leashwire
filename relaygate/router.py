import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse


class HttpDispatcher:
    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = set(allowed_hosts or [])

    def _resolve(self, url):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.fragment):
            raise ValueError("invalid handler URL")
        if self.allowed_hosts and parsed.hostname not in self.allowed_hosts:
            raise ValueError("handler host not allowed")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        answers = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        addresses = []
        for answer in answers:
            address = answer[4][0]
            ip = ipaddress.ip_address(address)
            if not ip.is_global or ip.is_multicast:
                raise ValueError("private handler address blocked")
            addresses.append(address)
        if not addresses:
            raise ValueError("handler has no addresses")
        return parsed, port, addresses

    def _validate(self, url):
        self._resolve(url)

    def send(self, url, payload):
        parsed, port, addresses = self._resolve(url)
        # Connect to the checked numeric address. HTTP Host and TLS verification
        # continue to use the original hostname; no second hostname lookup occurs.
        connection = http.client.HTTPConnection(parsed.hostname, port, timeout=10)
        try:
            connection.sock = socket.create_connection((addresses[0], port), timeout=10)
            if parsed.scheme == "https":
                connection.sock = ssl.create_default_context().wrap_socket(
                    connection.sock, server_hostname=parsed.hostname)
            target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            data = json.dumps(payload, separators=(",", ":")).encode()
            connection.request("POST", target, data, {"Content-Type": "application/json"})
            response = connection.getresponse()
            # Redirects are deliberately not followed.
            if not 200 <= response.status < 300:
                raise OSError("handler rejected event")
            return response.status
        finally:
            connection.close()


class FakeDispatcher:
    def __init__(self, failures=0):
        self.calls = []
        self.failures = failures

    def send(self, url, payload):
        self.calls.append((url, payload))
        if len(self.calls) <= self.failures:
            raise OSError("fake failure")
        return 200


def shape(kind, event):
    if kind == "langchain":
        return event
    if kind == "mcp":
        return {"jsonrpc": "2.0", "method": "notifications/relaygate/event", "params": event}
    if kind in ("retell", "vapi"):
        return {"event": event["type"], "data": event}
    raise ValueError("unknown handler kind")


class Router:
    def __init__(self, dispatcher, audit, sleeper=time.sleep):
        self.dispatcher = dispatcher
        self.audit = audit
        self.sleeper = sleeper

    def dispatch(self, agent, event):
        payload = shape(agent["handler_kind"], event)
        fields = dict(workspace=agent["ws"], agent_id=agent["id"], event="route.attempt",
                      recipient_token=event.get("recipient_token"), provider=event.get("provider"))
        for attempt in range(3):
            try:
                status = self.dispatcher.send(agent["handler_url"], payload)
                if not 200 <= status < 300:
                    raise OSError("handler rejected event")
            except Exception:
                self.audit.append(**fields, decision="block", reason="dispatch_error")
                if attempt < 2:
                    self.sleeper(.01 * (2 ** attempt))
            else:
                # Audit failures must propagate, never retry a successful delivery.
                self.audit.append(**fields, decision="allow", reason=f"dispatch_{status}")
                return True
        return False
