import base64
import hashlib
import hmac
import io
import json
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from relaygate.server import APIHandler, MAX_BODY, Throttle


class ServerLockRegressionTests(unittest.TestCase):
    def setUp(self):
        self.lock = threading.Lock()
        result = Mock(status=200)
        result.as_dict.return_value = {"ok": True}
        self.app = {
            "lock": self.lock,
            "admin_token": "admin-secret",
            "pipeline": Mock(),
            "inbound": Mock(),
            "audit": Mock(),
            "webhooks": {
                "twilio": {
                    "auth_token": "secret",
                    "public_url": "https://example.test/webhooks/twilio",
                },
                "telnyx": {"public_key": "test-key"},
            },
        }
        self.app["pipeline"].send.return_value = result
        self.app["inbound"].handle_message.return_value = True
        self.app["audit"].rows.return_value = []
        self.throttle = Throttle(limit=100)

    def handler(self, path, body=b"{}", headers=None):
        handler = object.__new__(APIHandler)
        handler.app = self.app
        handler.path = path
        handler.headers = {"Content-Length": str(len(body)), **(headers or {})}
        handler.client_address = ("test", 1)
        handler.throttle = self.throttle
        handler.connection = Mock()
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        return handler

    def assert_status(self, handler, status):
        handler.send_response.assert_called_once_with(status)

    def signed_stop(self):
        params = {
            "MessageSid": "SM-test",
            "From": "+14155550100",
            "To": "+14155550101",
            "Body": "STOP",
        }
        url = self.app["webhooks"]["twilio"]["public_url"]
        signed = url + "".join(key + params[key] for key in sorted(params))
        signature = base64.b64encode(
            hmac.new(b"secret", signed.encode(), hashlib.sha1).digest()
        ).decode()
        return self.handler(
            "/webhooks/twilio", urlencode(params).encode(),
            {"X-Twilio-Signature": signature},
        )

    def test_stalled_public_bodies_do_not_block_stop_sends_or_dashboard(self):
        for path in ("/v1/messages", "/webhooks/twilio", "/webhooks/telnyx"):
            with self.subTest(path=path):
                entered = threading.Event()
                release = threading.Event()
                finished = threading.Event()
                errors = []
                stalled = self.handler(path)
                stalled.headers["Content-Length"] = str(MAX_BODY)

                def read(size):
                    entered.set()
                    if not release.wait(3):
                        raise TimeoutError("test body stalled")
                    return b""

                stalled.rfile = Mock()
                stalled.rfile.read1.side_effect = read
                slow_thread = threading.Thread(target=stalled.do_POST, daemon=True)

                def other_requests():
                    try:
                        stop = self.signed_stop()
                        stop.do_POST()
                        self.assert_status(stop, 200)
                        message = self.handler("/v1/messages")
                        message.do_POST()
                        self.assert_status(message, 200)
                        dashboard = self.handler("/")
                        dashboard.do_GET()
                        self.assert_status(dashboard, 200)
                        audit = self.handler(
                            "/v1/audit", headers={"Authorization": "Bearer admin-secret"})
                        audit.do_GET()
                        self.assert_status(audit, 200)
                    except BaseException as exc:
                        errors.append(exc)
                    finally:
                        finished.set()

                other_thread = threading.Thread(target=other_requests, daemon=True)
                slow_thread.start()
                try:
                    self.assertTrue(entered.wait(1))
                    other_thread.start()
                    self.assertTrue(finished.wait(1), "body read blocked unrelated requests")
                    self.assertEqual(errors, [])
                    self.assertTrue(slow_thread.is_alive())
                finally:
                    release.set()
                    slow_thread.join(4)
                    if other_thread.ident is not None:
                        other_thread.join(4)
                self.assertFalse(slow_thread.is_alive())

    def test_public_throttle_rejects_before_body_read_or_service_call(self):
        for path in ("/v1/messages", "/webhooks/twilio", "/webhooks/telnyx", "/webhooks/unknown"):
            with self.subTest(path=path):
                handler = self.handler(path)
                handler.throttle = Throttle(limit=0)
                handler.rfile = Mock()
                handler.do_POST()
                self.assert_status(handler, 429)
                handler.rfile.read.assert_not_called()
                handler.rfile.read1.assert_not_called()
                self.assertTrue(handler.close_connection)
        self.app["pipeline"].send.assert_not_called()
        self.app["inbound"].handle_message.assert_not_called()

    def test_message_throttle_does_not_consume_stop_budget(self):
        self.throttle = Throttle(limit=1)
        first = self.handler("/v1/messages")
        first.do_POST()
        self.assert_status(first, 200)
        second = self.handler("/v1/messages")
        second.do_POST()
        self.assert_status(second, 429)
        stop = self.signed_stop()
        stop.do_POST()
        self.assert_status(stop, 200)
        repeated_stop = self.signed_stop()
        repeated_stop.do_POST()
        self.assert_status(repeated_stop, 429)

    def test_socket_timeout_returns_408_without_service_calls(self):
        handler = self.handler("/v1/messages")
        handler.rfile = Mock()
        handler.rfile.read1.side_effect = TimeoutError("stalled")
        handler.do_POST()
        self.assert_status(handler, 408)
        self.assertEqual(json.loads(handler.wfile.getvalue()), {"reason": "request_timeout"})
        self.assertTrue(handler.close_connection)
        budgets = [call.args[0] for call in handler.connection.settimeout.call_args_list]
        self.assertTrue(budgets)
        self.assertTrue(all(0 < budget <= APIHandler.timeout for budget in budgets))
        self.app["pipeline"].send.assert_not_called()
        self.assertFalse(self.lock.locked())

    def test_trickle_body_has_total_deadline(self):
        handler = self.handler("/v1/messages")
        handler.rfile = Mock()
        handler.rfile.read1.return_value = b"{"
        with patch("relaygate.server.time.monotonic", side_effect=[0, 0, 11]):
            with self.assertRaises(TimeoutError):
                handler._body()
        handler.rfile.read1.assert_called_once_with(2)
        handler.connection.settimeout.assert_called_with(APIHandler.timeout)

    def test_handler_setup_applies_socket_timeout(self):
        handler = object.__new__(APIHandler)
        handler.request = Mock()
        handler.setup()
        handler.request.settimeout.assert_called_once_with(APIHandler.timeout)

    def test_malformed_bodies_never_reach_service(self):
        cases = (
            (b"{", "1", 400),
            (b"[]", "2", 400),
            (b"{}", "3", 422),
            (b"", str(MAX_BODY + 1), 413),
            (b"{}", "-1", 422),
        )
        for body, length, expected in cases:
            with self.subTest(body=body, length=length):
                handler = self.handler("/v1/messages", body)
                handler.headers["Content-Length"] = length
                handler.do_POST()
                self.assert_status(handler, expected)
                self.assertFalse(self.lock.locked())
        self.app["pipeline"].send.assert_not_called()

    def test_service_calls_are_locked_but_response_writes_are_not(self):
        result = self.app["pipeline"].send.return_value

        def send(*args, **kwargs):
            self.assertTrue(self.lock.locked())
            return result

        def inbound(*args, **kwargs):
            self.assertTrue(self.lock.locked())
            return True

        def rows():
            self.assertTrue(self.lock.locked())
            return []

        self.app["pipeline"].send.side_effect = send
        self.app["inbound"].handle_message.side_effect = inbound
        self.app["audit"].rows.side_effect = rows
        handlers = (
            (self.handler("/v1/messages"), "POST"),
            (self.signed_stop(), "POST"),
            (self.handler("/"), "GET"),
            (self.handler("/dashboard.js"), "GET"),
            (self.handler("/v1/audit", headers={"Authorization": "Bearer admin-secret"}), "GET"),
            (self.handler("/v1/audit"), "GET"),
            (self.handler("/v1/messages", b"{"), "POST"),
        )
        for handler, method in handlers:
            with self.subTest(path=handler.path, method=method):
                checks = []

                def check_unlocked(*args, **kwargs):
                    checks.append(self.lock.locked())

                handler.send_response.side_effect = check_unlocked
                handler.send_header.side_effect = check_unlocked
                handler.end_headers.side_effect = check_unlocked
                handler.wfile = Mock()
                handler.wfile.write.side_effect = check_unlocked
                getattr(handler, "do_" + method)()
                self.assertTrue(checks)
                self.assertFalse(any(checks), "response I/O held application lock")


if __name__ == "__main__":
    unittest.main()
