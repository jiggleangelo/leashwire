import io
import json
import runpy
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from relaygate.cli import build
from relaygate.demo import FakeClock, run_demo
from relaygate.providers.base import ProviderError


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.urlopen = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        self.connect = patch("socket.create_connection", side_effect=AssertionError("network forbidden"))
        self.url_mock = self.urlopen.start()
        self.socket_mock = self.connect.start()
        self.addCleanup(self.urlopen.stop)
        self.addCleanup(self.connect.stop)
        self.addCleanup(self.url_mock.assert_not_called)
        self.addCleanup(self.socket_mock.assert_not_called)

    def close_app(self, app):
        self.addCleanup(app["db"].close)
        self.addCleanup(app["vault"]._db.close)

    def fixture(self, cap=5):
        clock = FakeClock()
        app = build(key=b"test-key-with-at-least-32-bytes!!!", clock=clock)
        self.close_app(app)
        db = app["db"]
        db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?)", (
            "w", "Work", "Work support. Reply STOP to opt out.", "{}", '{"fake":{"outbound":0.01}}',
        ))
        db.commit()
        agent_id, key = app["keys"].provision_agent("w", "one", "fake", (cap, 10), sender="sender-test", handler_url="demo://test")
        sender = "+14155550101"
        db.execute("INSERT INTO senders VALUES(?,?,?,?,?,?)", (
            app["vault"].identify(sender, "w"), "w", agent_id, "fake", "relaygate", 0,
        ))
        db.commit()
        return app, clock, sender, agent_id, key

    def test_full_core_flow(self):
        app, checks = run_demo()
        self.close_app(app)
        self.assertGreaterEqual(len(checks), 15)
        for label, passed in checks.items():
            with self.subTest(check=label):
                self.assertTrue(passed)
        db = app["db"]
        capped = app["demo_agents"]["capped"]
        self.assertEqual(db.execute("SELECT status FROM agents WHERE id=?", (capped,)).fetchone()[0], "suspended_cap")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM sends WHERE agent_id=? AND status='sent'", (capped,)).fetchone()[0], 1)
        self.assertAlmostEqual(app["spend"].totals(capped)[0], .014)
        rows = [json.loads(row[0]) for row in db.execute("SELECT row_json FROM audit ORDER BY seq")]
        sent_ids = {row.get("provider_msg_id") for row in rows if row["event"] == "message.sent"}
        for row in db.execute("SELECT provider_msg_id FROM sends WHERE status='sent'"):
            self.assertIn(row[0], sent_ids)
        stop_index = next(i for i, row in enumerate(rows) if row.get("reason") == "inbound_stop")
        route_index = next(i for i, row in enumerate(rows) if row["event"] == "route.attempt")
        self.assertLess(stop_index, route_index)
        self.assertTrue(app["audit"].verify_chain())
        db.execute("UPDATE audit SET row_json='{}' WHERE seq=1")
        db.commit()
        self.assertFalse(app["audit"].verify_chain())

    def test_module_entry_point(self):
        output = io.StringIO()
        with patch("sys.argv", ["relaygate", "demo"]), redirect_stdout(output):
            runpy.run_module("relaygate.__main__", run_name="__main__")
        self.assertIn("spend cap blocks and suspends: OK", output.getvalue())
        self.assertIn("audit chain: OK", output.getvalue())
        self.assertIn("agent routing: OK", output.getvalue())
        self.assertNotIn("FAILED", output.getvalue())

    def test_replies_are_per_recipient_and_rolling_24_hours(self):
        app, clock, sender, agent, key = self.fixture()
        numbers = ("+14155550100", "+14155550104")
        inbound = app["inbound"].handle_message
        for word in ("STOP", "HELP", "START"):
            for number in numbers:
                self.assertTrue(inbound("fake", number, sender, word, word + number))
        self.assertEqual(len(app["provider"].sent), 6)
        for number in numbers:
            self.assertEqual(sum(row["to"] == number for row in app["provider"].sent), 3)
            self.assertTrue(app["consent"].check("w", app["vault"].identify(number, "w")).allow)
        rows = list(app["db"].execute("SELECT rcpt,keyword FROM compliance_replies"))
        self.assertEqual(len(rows), 6)
        self.assertEqual(len({tuple(row) for row in rows}), 6)
        idem_rows = list(app["db"].execute("SELECT rcpt,idem_key FROM sends WHERE status='sent'"))
        self.assertEqual(len({row[1] for row in idem_rows}), 6)
        for token, idem in idem_rows:
            self.assertIn(token, idem)
        clock.advance(hours=1)
        for word in ("STOP", "HELP", "START"):
            for number in numbers:
                self.assertTrue(inbound("fake", number, sender, word, "repeat-" + word + number))
        self.assertEqual(len(app["provider"].sent), 6)
        clock.advance(hours=24)
        for word in ("STOP", "HELP", "START"):
            for number in numbers:
                self.assertTrue(inbound("fake", number, sender, word, "later-" + word + number))
        self.assertEqual(len(app["provider"].sent), 12)
        self.assertEqual(app["db"].execute("SELECT COUNT(*) FROM compliance_replies").fetchone()[0], 12)

    def test_failed_compliance_delivery_is_not_recorded_and_can_retry(self):
        app, clock, sender, agent, key = self.fixture()
        number = "+14155550100"
        with patch.object(app["vault"], "deliver", side_effect=ProviderError("temporary failure")):
            self.assertTrue(app["inbound"].handle_message("fake", number, sender, "HELP", "failed-help"))
        self.assertEqual(len(app["provider"].sent), 0)
        self.assertEqual(app["db"].execute("SELECT COUNT(*) FROM compliance_replies").fetchone()[0], 0)
        self.assertTrue(app["inbound"].handle_message("fake", number, sender, "HELP", "retry-help"))
        self.assertEqual(len(app["provider"].sent), 1)
        self.assertEqual(app["db"].execute("SELECT COUNT(*) FROM compliance_replies").fetchone()[0], 1)

    def test_compliance_reply_obeys_spend_cap_and_stop_still_revokes(self):
        app, clock, sender, agent, key = self.fixture(cap=.01)
        number = "+14155550100"
        token = app["vault"].identify(number, "w")
        app["consent"].grant("w", token, "web_form", "form#test", agent)
        self.assertTrue(app["inbound"].handle_message("fake", number, sender, "STOP", "capped-stop"))
        self.assertEqual(app["consent"].check("w", token).reason, "suppressed")
        self.assertEqual(len(app["provider"].sent), 0)
        self.assertEqual(app["db"].execute("SELECT COUNT(*) FROM compliance_replies").fetchone()[0], 0)
        self.assertEqual(app["db"].execute("SELECT status FROM agents WHERE id=?", (agent,)).fetchone()[0], "suspended_cap")
        self.assertEqual(app["router"].dispatcher.calls[-1][1]["type"], "consent.revoked")

    def test_digit_heavy_tokens_keep_consent_send_and_block_linkage(self):
        app, clock, sender, agent, key = self.fixture()
        number = "+14155550100"
        token = "rc_" + "12345678901234567890abcdefabcdef"
        self.assertEqual(len(token), 35)
        with patch.object(app["vault"], "identify", return_value=token):
            cid = app["consent"].grant("w", token, "web_form", "form#test", agent)
            self.assertTrue(app["pipeline"].send(key, number, "private regression body").ok)
            app["consent"].revoke("w", token, "api", agent_id=agent)
            self.assertEqual(app["pipeline"].send(key, number, "blocked body").reason, "suppressed")
        rows = [json.loads(row[0]) for row in app["db"].execute("SELECT row_json FROM audit")]
        linked = [row for row in rows if row["event"] in {"consent.changed", "message.sent", "message.blocked"}]
        self.assertEqual(len(linked), 4)
        self.assertTrue(all(row["recipient_token"] == token for row in linked))
        sent = next(row for row in linked if row["event"] == "message.sent")
        self.assertEqual(sent["consent_record_id"], cid)
        self.assertEqual(sent["consent_source"], "web_form")
        self.assertTrue(app["audit"].verify_chain())
        before = len(rows)
        for fields in (
            {"recipient_token": "+14155550100"},
            {"recipient_token": "rc_mail@example.com"},
            {"reason": "mail@example.com"},
            {"reason": "+14155550100"},
            {"reason": {"contact": number}},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                app["audit"].append(event="test", **fields)
        self.assertEqual(app["db"].execute("SELECT COUNT(*) FROM audit").fetchone()[0], before)

    def test_workspace_scoping_does_not_leak_consent(self):
        app, clock, sender, agent, key = self.fixture()
        number = "+14155550100"
        unscoped = app["vault"].tokenize(number)
        scoped = app["vault"].identify(number, "w")
        self.assertNotEqual(unscoped, scoped)
        app["consent"].grant("w", unscoped, "web_form", "form#unscoped", agent)
        self.assertEqual(app["pipeline"].send(key, number, "x").reason, "no_consent")
        app["consent"].grant("w", scoped, "web_form", "form#scoped", agent)
        self.assertTrue(app["pipeline"].send(key, number, "x").ok)

    def test_punctuated_yes_requires_recent_outbound_in_both_modes(self):
        app, clock, sender, agent, key = self.fixture()
        for mode in ("relaygate", "provider"):
            app["db"].execute("UPDATE senders SET keyword_mode=?", (mode,))
            app["db"].commit()
            for index, word in enumerate(("YES", "YES!", "yes.", " yes?! ")):
                number = "+141555502" + str(index).zfill(2)
                token = app["vault"].identify(number, "w")
                app["consent"].revoke("w", token, "api", agent_id=agent)
                self.assertTrue(app["inbound"].handle_message(
                    "fake", number, sender, word, mode + "-no-recent-" + str(index)))
                self.assertEqual(app["consent"].check("w", token).reason, "suppressed")
                app["consent"].grant("w", token, "web_form", "form#yes", agent)
                self.assertTrue(app["pipeline"].send(key, number, "recent outbound").ok)
                app["consent"].revoke("w", token, "api", agent_id=agent)
                self.assertTrue(app["inbound"].handle_message(
                    "fake", number, sender, word, mode + "-recent-" + str(index)))
                self.assertTrue(app["consent"].check("w", token).allow)
            clock.advance(hours=25)

    def test_unicode_estimate_keeps_wire_cost_pessimistic(self):
        from relaygate.spend import segments
        app, clock, sender, agent, key = self.fixture(cap=.03)
        number = "+14155550100"
        token = app["vault"].identify(number, "w")
        app["consent"].grant("w", token, "web_form", "form#unicode", agent)
        self.assertEqual(segments("🙂" * 71), 2)
        self.assertEqual(segments("🙂" * 71, wire=True), 3)
        result = app["pipeline"].send(key, number, "🙂" * 71)
        self.assertEqual(result.reason, "cap_exceeded")
        self.assertAlmostEqual(result.est_usd, .0375)
        self.assertEqual(app["provider"].sent, [])


if __name__ == "__main__":
    unittest.main()
