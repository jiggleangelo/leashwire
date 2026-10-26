import base64
import os
import tempfile
import unittest
from unittest.mock import patch

from relaygate.cli import build
from relaygate.consent import classify
from relaygate.ed25519 import verify
from relaygate.inbound import verify_twilio
from relaygate.router import shape
from relaygate.spend import segments


class RelaygateTests(unittest.TestCase):
    def setUp(self):
        self.net1 = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        self.net2 = patch("socket.create_connection", side_effect=AssertionError("network forbidden"))
        self.net1.start()
        self.net2.start()
        self.addCleanup(self.net1.stop)
        self.addCleanup(self.net2.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = build(":memory:", os.path.join(self.tmp.name, "vault.db"))
        self.db = self.app["db"]
        self.addCleanup(self.db.close)
        self.addCleanup(self.app["vault"]._db.close)
        self.db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?)", (
            "w", "Work", "Work support; reply STOP to opt out", "{}", '{"fake":{"outbound":0.01}}',
        ))
        self.db.execute("INSERT INTO provider_optout_codes VALUES('fake','OPT_OUT')")
        self.db.commit()

    def test_vault_is_deterministic_egress_only_and_forget(self):
        vault = self.app["vault"]
        a = vault.tokenize("(415) 555-0100")
        self.assertEqual(a, vault.tokenize("+1 415 555 0100"))
        self.assertFalse(hasattr(vault, "get"))
        got = []
        vault.register_egress("capture", lambda **kw: got.append(kw["to"]))
        vault.deliver(a, "capture")
        self.assertEqual(got, ["+14155550100"])
        vault.forget(a)
        self.assertRaises(KeyError, vault.deliver, a, "capture")

    def test_keys_consent_pipeline_idempotency_and_cross_agent_stop(self):
        one, key = self.app["keys"].provision_agent("w", "one", "fake", (1, 2), sender="+14155550101")
        two, key2 = self.app["keys"].provision_agent("w", "two", "fake", (1, 2), sender="+14155550102")
        number = "+14155550100"
        token = self.app["vault"].tokenize(number, "w")
        self.app["consent"].grant("w", token, "web_form", "form#abc", one)
        sent = self.app["pipeline"].send(key, number, "hello", idempotency_key="once")
        again = self.app["pipeline"].send(key, number, "hello", idempotency_key="once")
        self.assertTrue(sent.ok)
        self.assertEqual(sent.provider_msg_id, again.provider_msg_id)
        self.assertEqual(len(self.app["provider"].sent), 1)
        self.app["consent"].revoke("w", token, "inbound_stop", agent_id=two)
        blocked = self.app["pipeline"].send(key, number, "hello")
        self.assertEqual(blocked.reason, "suppressed")
        self.assertEqual(self.app["pipeline"].send(key2, number, "hello").reason, "suppressed")

    def test_public_sender_cannot_select_compliance_bypass(self):
        agent_id, key = self.app["keys"].provision_agent("w", "one", "fake", (1, 2), sender="+14155550101")
        number = "+14155550100"
        token = self.app["vault"].tokenize(number, "w")
        self.app["consent"].revoke("w", token, "inbound_stop", agent_id=agent_id)
        with self.assertRaises(TypeError):
            self.app["pipeline"].send(key, number, "bypass", message_type="compliance")
        blocked = self.app["pipeline"].send(key, number, "bypass")
        self.assertFalse(blocked.ok)
        self.assertEqual(blocked.reason, "suppressed")
        self.assertEqual(len(self.app["provider"].sent), 0)
        agent = self.app["keys"].authenticate(key, "messages:send")
        internal = self.app["pipeline"].send_internal(agent, token, "non-reply", reply=False)
        self.assertFalse(internal.ok)
        self.assertEqual(internal.reason, "suppressed")
        self.assertEqual(len(self.app["provider"].sent), 0)

    def test_no_consent_cap_and_provider_optout(self):
        agent, key = self.app["keys"].provision_agent("w", "one", "fake", (0.02, 1), sender="+14155550101")
        number = "+14155550100"
        self.assertEqual(self.app["pipeline"].send(key, number, "x").reason, "no_consent")
        token = self.app["vault"].tokenize(number, "w")
        self.app["consent"].grant("w", token, "api_attested", "case#x", agent)
        self.assertTrue(self.app["pipeline"].send(key, number, "x").ok)
        self.assertEqual(self.app["pipeline"].send(key, number, "x").reason, "cap_exceeded")
        other, other_key = self.app["keys"].provision_agent("w", "other", "fake", (1, 2))
        self.app["provider"].opted_out.add(number)
        self.assertEqual(self.app["pipeline"].send(other_key, number, "x").reason, "provider_optout")
        decision = self.app["consent"].check("w", token)
        self.assertFalse(decision.allow)
        self.assertEqual(decision.source, "provider_optout_error")
        self.assertEqual(self.app["spend"].totals(other), (0, 0))

    def test_keywords_segments_shapes_and_twilio_signature(self):
        for text in ("stop!", " UnSubscribe.", "QUIT"):
            self.assertEqual(classify(text), "stop")
        self.assertEqual(classify("yes"), "start")
        self.assertEqual(classify("help."), "help")
        self.assertIsNone(classify("please stop"))
        self.assertEqual(segments("a" * 160), 1)
        self.assertEqual(segments("a" * 161), 2)
        self.assertEqual(segments("🙂" * 71), 2)
        event = {"type": "message.received"}
        self.assertEqual(shape("mcp", event)["jsonrpc"], "2.0")
        self.assertEqual(shape("retell", event)["event"], "message.received")
        self.assertEqual(shape("vapi", event)["data"], event)
        import hashlib
        import hmac
        url = "https://example.test/hook"
        params = {"Body": "hello", "From": "x"}
        sig = base64.b64encode(hmac.new(b"secret", (url + "BodyhelloFromx").encode(), hashlib.sha1).digest()).decode()
        self.assertTrue(verify_twilio(url, params, sig, "secret"))
        self.assertFalse(verify_twilio(url, params, sig + "x", "secret"))

    def test_twilio_signature_rejects_empty_provider_secret(self):
        import hashlib
        import hmac
        url = "https://example.test/webhooks/twilio"
        params = {"Body": "START", "From": "+14155550100"}
        attacker_signature = base64.b64encode(hmac.new(b"", (url + "BodySTARTFrom+14155550100").encode(), hashlib.sha1).digest()).decode()
        self.assertFalse(verify_twilio(url, params, attacker_signature, ""))

    def test_ed25519_rfc8032_vector_and_audit_tamper_guard(self):
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(verify(pk, b"", sig))
        self.assertFalse(verify(pk, b"x", sig))
        audit = self.app["audit"]
        audit.append(workspace="w", event="test", decision="allow", reason="ok")
        self.assertTrue(audit.verify_chain())
        self.assertRaises(ValueError, audit.append, workspace="w", event="x", decision="x", reason="mail@example.com")
        self.db.execute("UPDATE audit SET row_json='{}' WHERE seq=1")
        self.db.commit()
        self.assertFalse(audit.verify_chain())

    def test_pii_not_in_application_db(self):
        agent, key = self.app["keys"].provision_agent("w", "one", "fake", (1, 2), sender="+14155550101")
        number = "+14155550100"
        token = self.app["vault"].tokenize(number, "w")
        self.app["consent"].grant("w", token, "web_form", "form#abc", agent)
        self.assertTrue(self.app["pipeline"].send(key, number, "private body").ok)
        dump = "\n".join(self.db.iterdump())
        self.assertNotIn(number, dump)
        self.assertNotIn("private body", dump)


if __name__ == "__main__":
    unittest.main()
