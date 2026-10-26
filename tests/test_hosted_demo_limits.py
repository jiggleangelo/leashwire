import io
import sqlite3
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import demo


class HostedLimitsTests(unittest.TestCase):
    def state(self):
        state = demo.build_demo()
        self.addCleanup(state.close)
        return state

    def test_long_emoji_cannot_brick_primary_and_reset_restores_flow(self):
        state = self.state()
        state.perform("grant", state.contact, "")
        for _ in range(2):
            state.perform("send", state.contact, "🙂" * 2000)
            self.assertIn("Send result: sent", state.last_result)
        state.perform("send", state.contact, "ordinary message")
        self.assertIn("Send result: sent", state.last_result)
        state.perform("reset", "", "")
        state.perform("send", state.contact, "hello")
        self.assertIn("no_consent", state.last_result)
        state.perform("grant", state.contact, "")
        state.perform("send", state.contact, "hello")
        self.assertIn("Send result: sent", state.last_result)

    def test_cap_experiment_is_repeatable(self):
        state = self.state()
        for _ in range(3):
            state.perform("cap", "", "")
            self.assertEqual(state.last_result, "Cap test: first=sent; second=cap_exceeded.")
            self.assertTrue(state.app["audit"].verify_chain())

    def test_page_loads_do_not_verify_or_append_history(self):
        state = self.state()
        state.perform("grant", state.contact, "")
        state.perform("send", state.contact, "message")
        before = state.app["db"].total_changes
        with patch.object(state.app["audit"], "verify_chain", side_effect=AssertionError("GET scanned audit")):
            for _ in range(20):
                self.assertIn("Audit chain: <strong>verified</strong>", state.render())
        self.assertEqual(state.app["db"].total_changes, before)

    def test_all_histories_are_bounded_and_old_databases_closed(self):
        state = self.state()
        old_db = state.app["db"]
        old_vault = state.app["vault"]._db
        # Unique contacts exercise consent, vault, inbound events, replies,
        # sends, audit and dispatcher storage, not just repeated no-op sends.
        for index in range(demo.MAX_ACTIONS * 2 + 1):
            state.perform("start", "+1415555%04d" % index, "")
            self.assertLessEqual(state.actions, demo.MAX_ACTIONS)
            self.assertLessEqual(len(state.app["provider"].sent), demo.MAX_ACTIONS)
            self.assertLessEqual(len(state.dispatcher.calls), demo.MAX_ACTIONS)
            for table in ("consent", "inbound_seen", "inbound_events", "sends", "compliance_replies"):
                self.assertLessEqual(state.app["db"].execute("SELECT COUNT(*) FROM " + table).fetchone()[0], demo.MAX_ACTIONS)
            self.assertLessEqual(state.app["db"].execute("SELECT COUNT(*) FROM audit").fetchone()[0], demo.MAX_ACTIONS * 8)
            self.assertLessEqual(state.app["vault"]._db.execute("SELECT COUNT(*) FROM vault").fetchone()[0], demo.MAX_ACTIONS)
        for connection in (old_db, old_vault):
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
        self.assertTrue(state.app["audit"].verify_chain())

    def test_session_capacity_expiration_and_forged_token(self):
        clock = Mock(return_value=0)
        sessions = demo.DemoSessions(maximum=2, ttl=10, clock=clock)
        self.addCleanup(sessions.close)
        first, state = sessions.run("", True, lambda state, token: state)
        second, _ = sessions.run("", True, lambda state, token: None)
        self.assertNotEqual(first, second)
        with self.assertRaises(demo.SessionUnavailable):
            sessions.run("", True, lambda *args: None)
        with self.assertRaises(demo.SessionUnavailable):
            sessions.run("forged", False, lambda *args: self.fail("used forged token"))
        self.assertFalse(state.closed)
        clock.return_value = 10
        sessions.reap()
        self.assertTrue(state.closed)
        self.assertEqual(sessions.sessions, {})
        with self.assertRaises(demo.SessionUnavailable):
            sessions.run(first, False, lambda *args: None)
        replacement, _ = sessions.run(first, True, lambda *args: None)
        self.assertNotEqual(first, replacement)

    def test_body_uses_total_deadline_despite_successful_trickle_reads(self):
        handler = object.__new__(demo.DemoHandler)
        handler.headers = {"Content-Length": "3"}
        handler.connection = Mock()
        handler.rfile = Mock()
        handler.rfile.read1.return_value = b"x"
        with patch("relaygate.server.time.monotonic", side_effect=[0, 0, 6, 11]):
            with self.assertRaises(TimeoutError):
                handler._body(raw=True)
        self.assertEqual(handler.rfile.read1.call_count, 2)
        self.assertEqual(handler.connection.settimeout.call_args.args, (handler.timeout,))

    def test_body_timeout_returns_408_without_touching_session(self):
        handler = object.__new__(demo.DemoHandler)
        handler.path = "/action"
        handler.headers = {"Content-Length": "3"}
        handler._body = Mock(side_effect=TimeoutError)
        handler._error_page = Mock()
        handler.server = Mock()
        handler.do_POST()
        self.assertEqual(handler._error_page.call_args.args[0], 408)
        handler.server.demo_state.run.assert_not_called()

    def server_stub(self):
        server = object.__new__(demo.DemoServer)
        server.slots = threading.BoundedSemaphore(1)
        server.global_throttle = Mock()
        server.global_throttle.allow.return_value = True
        server.ip_throttle = Mock()
        server.ip_throttle.allow.return_value = True
        server.shutdown_request = Mock()
        return server

    def test_worker_limit_rejects_before_spawning_and_releases_on_failure(self):
        server = self.server_stub()
        request = Mock()
        server.slots.acquire()
        with patch("http.server.ThreadingHTTPServer.process_request") as spawn:
            server.process_request(request, ("visitor", 1))
            spawn.assert_not_called()
        server.shutdown_request.assert_called_once_with(request)
        server.slots.release()
        with patch("http.server.ThreadingHTTPServer.process_request", side_effect=RuntimeError("spawn failed")):
            with self.assertRaises(RuntimeError):
                server.process_request(request, ("visitor", 1))
        self.assertTrue(server.slots.acquire(blocking=False))

    def test_connection_deadline_interrupts_slow_headers_and_worker_is_released(self):
        server = self.server_stub()
        server.slots.acquire()
        request = Mock()
        with patch("demo.threading.Timer") as timer_factory:
            timer = timer_factory.return_value
            def work(*args):
                deadline, expire = timer_factory.call_args.args
                self.assertEqual(deadline, demo.CONNECTION_DEADLINE)
                expire()
                request.shutdown.assert_called_once_with(demo.socket.SHUT_RDWR)
            with patch("http.server.ThreadingHTTPServer.process_request_thread", side_effect=work):
                server.process_request_thread(request, ("visitor", 1))
            timer.start.assert_called_once()
            timer.cancel.assert_called_once()
            timer.join.assert_called_once()
        self.assertTrue(server.slots.acquire(blocking=False))

    def test_throttled_connections_do_not_allocate_workers(self):
        server = self.server_stub()
        server.global_throttle.allow.return_value = False
        request = Mock()
        with patch("http.server.ThreadingHTTPServer.process_request") as spawn:
            server.process_request(request, ("visitor", 1))
            spawn.assert_not_called()
        server.shutdown_request.assert_called_once_with(request)
        self.assertTrue(server.slots.acquire(blocking=False))

    def test_missing_csrf_cannot_mutate_session(self):
        handler = object.__new__(demo.DemoHandler)
        handler.path = "/action"
        handler.headers = {"Content-Length": "12", "Cookie": demo.COOKIE + "=private-session"}
        handler.rfile = io.BytesIO(b"action=grant")
        handler._error_page = Mock()
        handler.server = SimpleNamespace(demo_state=Mock())
        handler.do_POST()
        self.assertEqual(handler._error_page.call_args.args[0], 403)
        handler.server.demo_state.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
