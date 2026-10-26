import base64
import hashlib
import hmac
import io
import json
import socket
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from relaygate.audit import AuditUnavailable
from relaygate.cli import build
from relaygate.demo import FakeClock
from relaygate.providers.base import SendResult
from relaygate.router import HttpDispatcher
from relaygate.server import APIHandler, Throttle
from relaygate.vault import Vault


class ReviewTests(unittest.TestCase):
    def setUp(self):
        for target in ("urllib.request.urlopen", "socket.create_connection"):
            guard = patch(target, side_effect=AssertionError("network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.app = build(clock=FakeClock(), key=b"review-test-key")
        self.addCleanup(self.app["db"].close)
        self.addCleanup(self.app["vault"]._db.close)
        self.app["db"].execute("INSERT INTO workspaces VALUES(?,?,?,?,?)",
                               ("w123456789012", "Work", "Work support; reply STOP", "{}", "{}"))
        self.app["db"].commit()
        with patch("relaygate.keys.secrets.token_hex", side_effect=["123456789012", "a" * 32, "b" * 64]):
            self.agent_id, self.key = self.app["keys"].provision_agent(
                "w123456789012", "Test", "fake", (1, 5), handler_url="demo://test", sender="sender-test")
        self.number = "+14155550100"
        self.sender = "+14155550101"
        self.token = self.app["vault"].identify(self.number, "w123456789012")
        self.app["db"].execute("INSERT INTO senders VALUES(?,?,?,?,?,?)", (
            self.app["vault"].identify(self.sender, "w123456789012"), "w123456789012",
            self.agent_id, "fake", "relaygate", 0))
        self.app["db"].commit()

    def grant(self):
        return self.app["consent"].grant("w123456789012", self.token, "web_form", "form#test", self.agent_id)

    def request(self, path, body=b"", headers=None, method="POST"):
        handler = object.__new__(APIHandler)
        handler.app = self.app
        handler.path = path
        handler.headers = {"Content-Length": str(len(body)), **(headers or {})}
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.client_address = ("test", 1)
        handler.throttle = Throttle(limit=100)
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        getattr(handler, "do_" + method)()
        return handler.send_response.call_args.args[0], handler.wfile.getvalue()

    def test_digit_heavy_identifiers_send_stop_start_and_routing(self):
        self.grant()
        for mid in ("SM" + "1234567890" * 3 + "ab", "12345678-9012-4012-8012-123456789012"):
            with patch.object(self.app["vault"], "deliver", return_value=SendResult(mid)):
                self.assertTrue(self.app["pipeline"].send(self.key, self.number, "private").ok)
        for word in ("STOP", "START"):
            self.assertTrue(self.app["inbound"].handle_message("fake", self.number, self.sender, word, word))
        self.assertEqual(len(self.app["router"].dispatcher.calls), 2)
        rows = [json.loads(row[0]) for row in self.app["db"].execute("SELECT row_json FROM audit")]
        self.assertEqual(sum(row["event"] == "message.sent" for row in rows), 4)
        self.assertTrue(self.app["audit"].verify_chain())
        for field in ("workspace", "agent_id", "provider_msg_id"):
            for value in (self.number, "mail@example.com", "14155550100"):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.app["audit"].append(event="test", **{field: value})

    def test_audit_outage_prevents_delivery(self):
        self.grant()
        with patch.object(self.app["audit"], "append", side_effect=OSError("offline")):
            with self.assertRaises(AuditUnavailable):
                self.app["pipeline"].send(self.key, self.number, "private", idempotency_key="once")
        self.assertEqual(self.app["provider"].sent, [])
        self.assertEqual(self.app["spend"].totals(self.agent_id), (0, 0))

    def test_post_delivery_audit_failure_is_visible_and_does_not_resend(self):
        self.grant()
        append = self.app["audit"].append

        def fail_sent(**fields):
            if fields.get("event") == "message.sent":
                raise OSError("offline")
            return append(**fields)

        with patch.object(self.app["audit"], "append", side_effect=fail_sent):
            with self.assertRaises(AuditUnavailable):
                self.app["pipeline"].send(self.key, self.number, "private", idempotency_key="once")
        self.assertTrue(self.app["pipeline"].send(self.key, self.number, "private", idempotency_key="once").ok)
        self.assertEqual(len(self.app["provider"].sent), 1)

    def test_router_does_not_retry_success_when_audit_fails(self):
        agent = self.app["keys"].authenticate(self.key, "messages:send")
        with patch.object(self.app["audit"], "append", side_effect=OSError("offline")):
            with self.assertRaises(OSError):
                self.app["router"].dispatch(agent, {"type": "message.received", "recipient_token": self.token})
        self.assertEqual(len(self.app["router"].dispatcher.calls), 1)

    def test_signed_webhook_then_scoped_send_full_http_handlers_without_sockets(self):
        url = "https://example.test/webhooks/twilio"
        self.app["webhooks"] = {"twilio": {"auth_token": "secret", "public_url": url}}
        params = {"MessageSid": "SM123456789012", "From": self.number, "To": self.sender, "Body": "START"}
        raw = urlencode(params).encode()
        status, _ = self.request("/webhooks/twilio", raw, {"X-Twilio-Signature": "invalid"})
        self.assertEqual(status, 403)
        self.assertEqual(self.app["provider"].sent, [])
        signature = base64.b64encode(hmac.new(b"secret", (url + "".join(k + params[k] for k in sorted(params))).encode(), hashlib.sha1).digest()).decode()
        for _ in range(2):
            status, _ = self.request("/webhooks/twilio", raw, {"X-Twilio-Signature": signature})
            self.assertEqual(status, 200)
        self.assertEqual(len(self.app["provider"].sent), 1)
        status, body = self.request("/v1/messages", json.dumps({"to": self.number, "body": "private"}).encode(), {"Authorization": "Bearer " + self.key})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertTrue(self.app["audit"].verify_chain())

    def test_dashboard_and_admin_data_auth(self):
        self.app["admin_token"] = "admin-secret"
        status, html = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertIn(b"/dashboard.js", html)
        self.assertNotIn(self.key.encode(), html)
        status, _ = self.request("/v1/agents", method="GET")
        self.assertEqual(status, 401)
        status, data = self.request("/v1/agents", headers={"Authorization": "Bearer admin-secret"}, method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["agents"][0]["id"], self.agent_id)
        self.assertNotIn(b"key_hash", data)

    def test_shared_connection_and_vault_work_across_threads(self):
        self.grant()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda i: self.app["pipeline"].send(
                self.key, self.number, "private", idempotency_key="parallel-" + str(i)), range(8)))
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(len(self.app["provider"].sent), 8)
        self.assertTrue(self.app["audit"].verify_chain())
        self.assertAlmostEqual(self.app["spend"].totals(self.agent_id)[0], .1)

    def test_pbkdf2_storage(self):
        row = self.app["db"].execute("SELECT key_hash,key_salt FROM agents WHERE id=?", (self.agent_id,)).fetchone()
        expected = hashlib.pbkdf2_hmac("sha256", self.key.encode(), bytes.fromhex(row[1]), 100000).hex()
        self.assertEqual(row[0], "pbkdf2_sha256$100000$" + expected)

    def test_vault_stream_partial_blocks_and_round_trip(self):
        for length in (0, 1, 12, 31, 32, 33, 65):
            with self.subTest(length=length):
                self.assertEqual(len(Vault._stream(b"key", b"nonce", length)), length)
                plain = "x" * length
                self.assertEqual(self.app["vault"]._unseal(self.app["vault"]._seal(plain)), plain)


class DispatcherTests(unittest.TestCase):
    def test_pins_checked_address_and_rejects_redirect(self):
        response = Mock(status=302)
        connection = Mock()
        connection.getresponse.return_value = response
        sock = Mock()
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        with patch("socket.getaddrinfo", return_value=addresses) as resolve, \
                patch("socket.create_connection", return_value=sock) as connect, \
                patch("http.client.HTTPConnection", return_value=connection):
            with self.assertRaises(OSError):
                HttpDispatcher().send("http://handler.example/path", {"type": "test"})
            resolve.assert_called_once()
            connect.assert_called_once_with(("93.184.216.34", 80), timeout=10)
            connection.request.assert_called_once()
            connection.close.assert_called_once()

    def test_private_dns_answer_rejected_before_connection(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=addresses), \
                patch("socket.create_connection", side_effect=AssertionError("network forbidden")) as connect:
            with self.assertRaises(ValueError):
                HttpDispatcher().send("http://handler.example/", {})
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
