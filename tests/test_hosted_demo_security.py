import io
import ipaddress
import threading
import unittest
from contextlib import redirect_stderr
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock, patch

import demo
from relaygate.server import Throttle


class HostedSecurityTests(unittest.TestCase):
    def sessions(self, **kwargs):
        sessions = demo.DemoSessions(**kwargs)
        self.addCleanup(sessions.close)
        return sessions

    def handler(self, server, peer="198.51.100.1", forwarded=None):
        handler = object.__new__(demo.DemoHandler)
        handler.server = server
        handler.client_address = (peer, 1234)
        handler.headers = Message()
        if forwarded is not None:
            handler.headers["X-Real-IP"] = forwarded
        handler.path = "/"
        handler._send = Mock()
        handler._error_page = Mock()
        return handler

    def server(self, proxies=()):
        server = object.__new__(demo.DemoServer)
        server.trusted_proxies = tuple(ipaddress.ip_network(value) for value in proxies)
        server.slots = threading.BoundedSemaphore(demo.MAX_WORKERS)
        server.peer_lock = threading.Lock()
        server.peer_workers = {}
        server.global_throttle = Throttle(limit=240, max_keys=1)
        server.ip_throttle = Throttle(limit=60, max_keys=512)
        server.shutdown_request = Mock()
        return server

    def test_cookieless_gets_cannot_exhaust_sessions_from_one_ip(self):
        sessions = self.sessions()
        server = self.server()
        server.demo_state = sessions
        with patch("demo.DemoState") as factory:
            factory.return_value.render.return_value = "page"
            for _ in range(60):
                self.handler(server).do_GET()
            self.assertEqual(len(sessions.sessions), demo.MAX_SESSIONS_PER_IP)
            self.assertEqual(factory.call_count, demo.MAX_SESSIONS_PER_IP)
            other = self.handler(server, "198.51.100.2")
            other.do_GET()
            self.assertEqual(other._send.call_args.args[0], 200)
            self.assertEqual(len(sessions.sessions), demo.MAX_SESSIONS_PER_IP + 1)

    def test_expiration_releases_owner_quota(self):
        clock = Mock(return_value=0)
        sessions = self.sessions(clock=clock, per_ip=1, ttl=10)
        with patch("demo.DemoState") as factory:
            first, _ = sessions.run("", True, lambda *args: None, owner="one")
            with self.assertRaises(demo.SessionUnavailable):
                sessions.run("", True, lambda *args: None, owner="one")
            clock.return_value = 10
            second, _ = sessions.run("", True, lambda *args: None, owner="one")
            self.assertNotEqual(first, second)
            self.assertEqual(len(sessions.sessions), 1)
            factory.return_value.close.assert_called_once()

    def test_slow_operation_does_not_block_other_session_or_reaper(self):
        sessions = self.sessions()
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        errors = []
        with patch("demo.DemoState"):
            first, _ = sessions.run("", True, lambda *args: None)
            second, _ = sessions.run("", True, lambda *args: None)
            def slow(*args):
                entered.set()
                if not release.wait(5):
                    raise AssertionError("test release timed out")
            def run_slow():
                try:
                    sessions.run(first, False, slow)
                except BaseException as exc:
                    errors.append(exc)
            def run_other():
                try:
                    sessions.reap()
                    sessions.run(second, False, lambda *args: completed.set())
                except BaseException as exc:
                    errors.append(exc)
            worker = threading.Thread(target=run_slow)
            other = threading.Thread(target=run_other)
            worker.start()
            try:
                self.assertTrue(entered.wait(2))
                other.start()
                self.assertTrue(completed.wait(2), "another session was serialized")
                with self.assertRaises(demo.SessionUnavailable):
                    sessions.run(first, False, lambda *args: None)
            finally:
                release.set()
                worker.join(5)
                if other.ident is not None:
                    other.join(5)
            self.assertEqual(errors, [])

    def test_initialization_reserves_capacity_without_holding_registry_lock(self):
        sessions = self.sessions(maximum=2)
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        errors = []
        state = Mock()
        def initialize():
            entered.set()
            if not release.wait(5):
                raise AssertionError("test release timed out")
            return state
        def create():
            try:
                sessions.run("", True, lambda *args: None, owner="new")
            except BaseException as exc:
                errors.append(exc)
        with patch("demo.DemoState", return_value=Mock()):
            existing, _ = sessions.run("", True, lambda *args: None)
        with patch("demo.DemoState", side_effect=initialize):
            worker = threading.Thread(target=create)
            worker.start()
            try:
                self.assertTrue(entered.wait(2))
                def other():
                    try:
                        with self.assertRaises(demo.SessionUnavailable):
                            sessions.run("", True, lambda *args: None)
                        sessions.run(existing, False, lambda *args: completed.set())
                    except BaseException as exc:
                        errors.append(exc)
                visitor = threading.Thread(target=other)
                visitor.start()
                self.assertTrue(completed.wait(2))
            finally:
                release.set()
                worker.join(5)
                if "visitor" in locals():
                    visitor.join(5)
        self.assertEqual(errors, [])

    def test_failed_initialization_releases_capacity_and_owner_quota(self):
        sessions = self.sessions(maximum=1, per_ip=1)
        with patch("demo.DemoState", side_effect=RuntimeError("failed")):
            with self.assertRaises(RuntimeError):
                sessions.run("", True, lambda *args: None, owner="one")
        self.assertEqual(sessions.sessions, {})
        with patch("demo.DemoState"):
            sessions.run("", True, lambda *args: None, owner="one")

    def test_expiration_and_close_do_not_dispose_an_active_state(self):
        clock = Mock(return_value=0)
        sessions = self.sessions(clock=clock, ttl=10)
        state = Mock()
        with patch("demo.DemoState", return_value=state):
            def operation(*args):
                clock.return_value = 10
                sessions.reap()
                sessions.close()
                state.close.assert_not_called()
                with self.assertRaises(demo.SessionUnavailable):
                    sessions.run("", True, lambda *args: None)
            sessions.run("", True, operation)
        state.close.assert_called_once()
        self.assertEqual(sessions.sessions, {})

    def test_unexpected_get_failure_returns_generic_page(self):
        server = self.server()
        server.demo_state = Mock()
        server.demo_state.run.side_effect = RuntimeError("private exception")
        handler = self.handler(server)
        handler.do_GET()
        self.assertEqual(handler._error_page.call_args.args, (500, "Demo temporarily unavailable."))

    def test_worker_exception_never_prints_peer_or_traceback(self):
        server = self.server()
        server.finish_request = Mock(side_effect=RuntimeError("private exception"))
        request = Mock()
        address = ("198.51.100.42", 1234)
        self.assertTrue(server._reserve_peer(address[0]))
        self.assertTrue(server.slots.acquire(False))
        output = io.StringIO()
        with redirect_stderr(output):
            server.process_request_thread(request, address)
        self.assertEqual(output.getvalue(), "")
        server.shutdown_request.assert_called_once_with(request)
        self.assertEqual(server.peer_workers, {})

    def test_three_slow_peers_cannot_occupy_all_workers(self):
        server = self.server()
        accepted = []
        with patch("http.server.ThreadingHTTPServer.process_request", side_effect=lambda request, address: accepted.append(address)):
            for peer in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
                for port in range(20):
                    server.process_request(Mock(), (peer, port))
            self.assertEqual(len(accepted), 3 * demo.MAX_WORKERS_PER_IP)
            server.process_request(Mock(), ("198.51.100.4", 1))
            self.assertEqual(len(accepted), 3 * demo.MAX_WORKERS_PER_IP + 1)
        self.assertEqual(len(server.peer_workers), 4)
        self.assertEqual(len(server.global_throttle.data["connections"]), len(accepted))

    def test_spawn_failure_releases_peer_and_global_slots(self):
        server = self.server()
        with patch("http.server.ThreadingHTTPServer.process_request", side_effect=RuntimeError("failed")):
            with self.assertRaises(RuntimeError):
                server.process_request(Mock(), ("198.51.100.1", 1))
        self.assertEqual(server.peer_workers, {})
        for _ in range(demo.MAX_WORKERS):
            self.assertTrue(server.slots.acquire(False))
        self.assertFalse(server.slots.acquire(False))

    def test_proxy_visitors_have_separate_budgets_and_session_quotas(self):
        server = self.server(("192.0.2.10/32",))
        sessions = self.sessions(per_ip=1)
        server.demo_state = sessions
        server.ip_throttle = Throttle(limit=1)
        with patch("demo.DemoState") as factory:
            factory.return_value.render.return_value = "page"
            for index in range(1, 4):
                handler = self.handler(server, "192.0.2.10", "198.51.100.%s" % index)
                handler.do_GET()
                self.assertEqual(handler._send.call_args.args[0], 200)
            repeated = self.handler(server, "192.0.2.10", "198.51.100.1")
            repeated.do_GET()
            self.assertEqual(repeated._error_page.call_args.args[0], 429)
        self.assertEqual(len(sessions.sessions), 3)
        self.assertNotIn("192.0.2.10", server.ip_throttle.data)

    def test_proxy_connections_do_not_share_peer_throttle_or_two_worker_limit(self):
        server = self.server(("192.0.2.10/32",))
        server.ip_throttle = Mock()
        with patch("http.server.ThreadingHTTPServer.process_request") as spawn:
            for port in range(4):
                server.process_request(Mock(), ("192.0.2.10", port))
            self.assertEqual(spawn.call_count, 4)
        server.ip_throttle.allow.assert_not_called()
        self.assertEqual(server.peer_workers, {})

    def test_forwarding_headers_are_trusted_only_from_explicit_proxy(self):
        server = self.server(("192.0.2.10/32",))
        direct = self.handler(server, "198.51.100.1", "198.51.100.2")
        self.assertEqual(direct._identity(), "198.51.100.1")
        for value in (None, "invalid", "198.51.100.1, 198.51.100.2"):
            with self.subTest(value=value):
                handler = self.handler(server, "192.0.2.10", value)
                self.assertIsNone(handler._admit())
                self.assertEqual(handler._error_page.call_args.args[0], 400)
        duplicate = self.handler(server, "192.0.2.10", "198.51.100.1")
        duplicate.headers["X-Real-IP"] = "198.51.100.2"
        with self.assertRaises(ValueError):
            duplicate._identity()


if __name__ == "__main__":
    unittest.main()
