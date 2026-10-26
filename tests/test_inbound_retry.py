import sqlite3
import unittest
from unittest.mock import Mock

from relaygate.inbound import Inbound


class InboundRetryTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            "CREATE TABLE inbound_events ("
            "provider TEXT, event_id TEXT, ts TEXT, "
            "PRIMARY KEY(provider, event_id));"
            "CREATE TABLE agents (id TEXT PRIMARY KEY, ws TEXT);"
            "INSERT INTO agents VALUES('a', 'w');"
        )
        self.db = Mock(wraps=self.connection)
        self.vault = Mock()
        self.vault.identify.return_value = "recipient-token"
        self.vault.persist.return_value = "recipient-token"
        self.consent = Mock()
        self.router = Mock()
        self.router.dispatch.return_value = True
        self.inbound = Inbound(
            self.db, self.vault, self.consent, Mock(), self.router, Mock()
        )
        self.inbound._mapping = Mock(return_value={
            "ws": "w",
            "agent_id": "a",
            "keyword_mode": "relaygate",
            "is_toll_free": False,
        })
        self.inbound._reply = Mock(return_value=True)

    def handle(self, body="STOP"):
        return self.inbound.handle_message(
            "fake", "+14155550100", "+14155550101", body, "event-1"
        )

    def assert_pending(self):
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM inbound_events").fetchone()[0],
            0,
        )

    def assert_retry_completes(self, body="STOP"):
        self.assertTrue(self.handle(body))
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM inbound_events").fetchone()[0],
            1,
        )
        calls = self.router.dispatch.call_count
        self.assertTrue(self.handle(body))
        self.assertEqual(self.router.dispatch.call_count, calls)

    def test_stop_retries_after_revoke_failure(self):
        self.consent.revoke.side_effect = [sqlite3.OperationalError("database is locked"), None]
        with self.assertRaises(sqlite3.OperationalError):
            self.handle()
        self.assert_pending()
        self.vault.persist.assert_not_called()
        self.assert_retry_completes()
        self.assertEqual(self.consent.revoke.call_count, 2)

    def test_stop_is_revoked_before_vault_failure_and_retry_is_processed(self):
        def fail_persist(*args):
            self.consent.revoke.assert_called_once_with(
                "w", "recipient-token", "inbound_stop", "sms", "a"
            )
            raise RuntimeError("vault unavailable")

        self.vault.persist.side_effect = fail_persist
        with self.assertRaises(RuntimeError):
            self.handle()
        self.assert_pending()
        self.vault.persist.side_effect = None
        self.assert_retry_completes()

    def test_stop_is_revoked_before_agent_lookup_failure(self):
        def execute(sql, parameters=()):
            if sql.startswith("SELECT * FROM agents"):
                self.consent.revoke.assert_called_once()
                raise sqlite3.OperationalError("database is locked")
            return self.connection.execute(sql, parameters)

        self.db.execute.side_effect = execute
        with self.assertRaises(sqlite3.OperationalError):
            self.handle()
        self.assert_pending()
        self.db.execute.side_effect = None
        self.assert_retry_completes()

    def test_missing_agent_does_not_complete_event_or_prevent_revocation(self):
        self.connection.execute("DELETE FROM agents")
        self.connection.commit()
        self.assertFalse(self.handle())
        self.consent.revoke.assert_called_once()
        self.assert_pending()
        self.connection.execute("INSERT INTO agents VALUES('a', 'w')")
        self.connection.commit()
        self.assert_retry_completes()

    def test_start_retries_after_grant_failure(self):
        self.consent.grant.side_effect = [RuntimeError("grant failed"), None]
        with self.assertRaises(RuntimeError):
            self.handle("START")
        self.assert_pending()
        self.assert_retry_completes("START")
        self.assertEqual(self.consent.grant.call_count, 2)

    def test_failures_after_revocation_leave_event_retryable(self):
        for target in (
            self.consent.note_inbound,
            self.inbound._reply,
            self.router.dispatch,
        ):
            with self.subTest(target=target):
                self.connection.execute("DELETE FROM inbound_events")
                self.connection.commit()
                target.side_effect = RuntimeError("temporary failure")
                with self.assertRaises(RuntimeError):
                    self.handle()
                self.assert_pending()
                self.consent.revoke.assert_called_with(
                    "w", "recipient-token", "inbound_stop", "sms", "a"
                )
                target.side_effect = None
                self.assert_retry_completes()

    def test_unsuccessful_dispatch_leaves_event_retryable(self):
        self.router.dispatch.return_value = False
        self.assertFalse(self.handle())
        self.assert_pending()
        self.router.dispatch.return_value = True
        self.assert_retry_completes()

    def test_dedupe_read_errors_are_not_reported_as_success(self):
        self.db.execute.side_effect = sqlite3.OperationalError("database is locked")
        with self.assertRaises(sqlite3.OperationalError):
            self.handle()
        self.assert_pending()
        self.db.execute.side_effect = None
        self.assert_retry_completes()

    def test_dedupe_insert_failure_leaves_event_retryable(self):
        def execute(sql, parameters=()):
            if sql.startswith("INSERT OR IGNORE INTO inbound_events"):
                raise sqlite3.OperationalError("database is locked")
            return self.connection.execute(sql, parameters)

        self.db.execute.side_effect = execute
        with self.assertRaises(sqlite3.OperationalError):
            self.handle()
        self.consent.revoke.assert_called_once()
        self.assert_pending()
        self.db.execute.side_effect = None
        self.assert_retry_completes()

    def test_dedupe_commit_failure_rolls_back_marker(self):
        self.db.commit.side_effect = sqlite3.OperationalError("database is locked")
        with self.assertRaises(sqlite3.OperationalError):
            self.handle()
        self.db.rollback.assert_called_once()
        self.assert_pending()
        self.db.commit.side_effect = None
        self.assert_retry_completes()


if __name__ == "__main__":
    unittest.main()
