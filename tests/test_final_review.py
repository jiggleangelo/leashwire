import base64
import hashlib
import hmac
import io
import json
import os
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from relaygate.cli import build, production_build
from relaygate.consent import classify
from relaygate.demo import FakeClock
from relaygate.providers.base import ProviderError
from relaygate.providers.telnyx import TelnyxProvider
from relaygate.providers.twilio import TwilioProvider
from relaygate.server import APIHandler, Throttle


class FinalReviewTests(unittest.TestCase):
    def setUp(self):
        for name in ("urllib.request.urlopen", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("network forbidden"))
            mocked = guard.start()
            self.addCleanup(guard.stop)
            self.addCleanup(mocked.assert_not_called)

    def close_app(self, app):
        self.addCleanup(app["db"].close)
        self.addCleanup(app["vault"]._db.close)

    def test_keyword_matching_does_not_join_words_or_remove_digits(self):
        for body in ("S TOP", "ST-OP", "STOP123", "YES please", "Y E S", "!YES"):
            self.assertIsNone(classify(body))
        for body in ("YES!", "yes.", " YES?! "):
            self.assertEqual(classify(body), "start")

    def test_throttle_is_bounded_and_expires_inactive_keys(self):
        throttle = Throttle(limit=2, max_keys=3)
        with patch("relaygate.server.time.monotonic", return_value=0):
            for key in ("a", "b", "c"):
                self.assertTrue(throttle.allow(key))
            for index in range(100):
                self.assertFalse(throttle.allow("new-" + str(index)))
            self.assertEqual(len(throttle.data), 3)
            self.assertTrue(throttle.allow("a"))
            self.assertFalse(throttle.allow("a"))
        with patch("relaygate.server.time.monotonic", return_value=60):
            self.assertTrue(throttle.allow("new"))
            self.assertEqual(list(throttle.data), ["new"])

    def webhook(self, app, throttle, params, valid=True):
        raw = urlencode(params).encode()
        url = app["webhooks"]["twilio"]["public_url"]
        signature = base64.b64encode(hmac.new(
            b"secret", (url + "".join(k + params[k] for k in sorted(params))).encode(),
            hashlib.sha1,
        ).digest()).decode()
        handler = object.__new__(APIHandler)
        handler.app = app
        handler.path = "/webhooks/twilio"
        handler.client_address = ("reverse-proxy", 1)
        handler.throttle = throttle
        handler.headers = {"Content-Length": str(len(raw)),
                           "X-Twilio-Signature": signature if valid else "invalid"}
        handler.rfile = io.BytesIO(raw)
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.do_POST()
        return handler.send_response.call_args.args[0]

    def test_proxy_burst_preserves_stop_and_unmapped_destinations_are_acknowledged(self):
        app = build(clock=FakeClock(), key=b"review-key")
        self.close_app(app)
        app["webhooks"] = {"twilio": {
            "auth_token": "secret", "public_url": "https://example.test/webhooks/twilio",
        }}
        db = app["db"]
        db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?)",
                   ("w", "Work", "Work support; STOP", "{}", "{}"))
        db.commit()
        agent, key = app["keys"].provision_agent("w", "agent", "fake", (10, 20), handler_url="demo://test")
        sender = "+14155550101"
        number = "+14155550100"
        token = app["vault"].identify(number, "w")
        db.execute("INSERT INTO senders VALUES(?,?,?,?,?,?)",
                   (app["vault"].identify(sender, "w"), "w", agent, "fake", "provider", 1))
        db.commit()
        app["consent"].grant("w", token, "web_form", "form#test", agent)
        throttle = Throttle(limit=1)
        for index in range(40):
            params = {"MessageSid": "SM-test-" + str(index), "From": number,
                      "To": sender, "Body": "HELP"}
            self.assertEqual(self.webhook(app, throttle, params), 200)
        params.update(MessageSid="SM-stop", Body="STOP")
        self.assertEqual(self.webhook(app, throttle, params, valid=False), 403)
        self.assertTrue(app["consent"].check("w", token).allow)
        self.assertEqual(self.webhook(app, throttle, params), 200)
        self.assertEqual(app["consent"].check("w", token).reason, "suppressed")
        calls = len(app["router"].dispatcher.calls)
        params.update(MessageSid="SM-unmapped", To="+14155550999")
        self.assertEqual(self.webhook(app, throttle, params), 200)
        self.assertEqual(len(app["router"].dispatcher.calls), calls)
        self.assertEqual(app["provider"].sent, [])
        self.assertTrue(app["audit"].verify_chain())
        self.assertNotIn(number, "\n".join(db.iterdump()))

    def test_production_build_selects_live_adapters_without_network(self):
        environment = {
            "RELAYGATE_VAULT_KEY": "production-builder-test-key",
            "RELAYGATE_DB": ":memory:", "RELAYGATE_VAULT_DB": ":memory:",
            "RELAYGATE_PROVIDERS": "telnyx,twilio",
            "TELNYX_API_KEY": "telnyx-secret", "TWILIO_ACCOUNT_SID": "ACtest",
            "TWILIO_AUTH_TOKEN": "twilio-secret",
        }
        with patch.dict(os.environ, environment, clear=True):
            app = production_build()
        self.close_app(app)
        self.assertEqual(set(app["providers"]), {"telnyx", "twilio"})
        self.assertIsInstance(app["providers"]["telnyx"], TelnyxProvider)
        self.assertIsInstance(app["providers"]["twilio"], TwilioProvider)
        self.assertTrue(app["unthrottled_webhooks"])
        self.assertIs(app["vault"]._egress["telnyx"].__self__, app["providers"]["telnyx"])
        self.assertIs(app["vault"]._egress["twilio"].__self__, app["providers"]["twilio"])

    def test_telnyx_sets_verifies_then_enables_native_cap(self):
        provider = TelnyxProvider("secret")
        responses = [
            {"data": {"id": "profile-test"}},
            {"data": {"daily_spend_limit": "2.5", "daily_spend_limit_enabled": True}},
            {"data": {"enabled": True}},
        ]
        with patch.object(provider, "_call", side_effect=responses) as call:
            self.assertEqual(provider.provision_agent_scope("ag_test", 2.5), "profile-test")
        payload = call.call_args_list[0].args[1]
        self.assertEqual(payload["daily_spend_limit"], "2.5")
        self.assertTrue(payload["daily_spend_limit_enabled"])
        self.assertFalse(payload["enabled"])
        self.assertEqual(call.call_args_list[1].kwargs["method"], "GET")
        self.assertEqual(call.call_args_list[2].args[1], {"enabled": True})

    def test_telnyx_does_not_enable_a_profile_without_confirmed_cap(self):
        provider = TelnyxProvider("secret")
        with patch.object(provider, "_call", side_effect=[
            {"data": {"id": "profile-test"}},
            {"data": {"daily_spend_limit": "100", "daily_spend_limit_enabled": True}},
        ]) as call:
            with self.assertRaises(ProviderError):
                provider.provision_agent_scope("ag_test", 2.5)
        self.assertEqual(call.call_count, 2)

    def test_twilio_never_fabricates_provisioning_or_uses_parent_credentials(self):
        provider = TwilioProvider("ACparent", "parent-secret")
        with self.assertRaises(ProviderError):
            provider.provision_agent_scope("ag_test", 2)
        with self.assertRaises(ProviderError):
            provider.send(to="+14155550100", sender="+14155550101", body="private", ref="missing")
        controller = Mock()
        controller.provision_agent_scope.return_value = "scope-test"
        controller.verify_agent_scope.return_value = True
        provider = TwilioProvider("ACparent", "parent-secret", controller)
        self.assertEqual(provider.provision_agent_scope("ag_test", 2), "scope-test")
        controller.provision_agent_scope.assert_called_once_with("ag_test", 2.0)
        controller.verify_agent_scope.assert_called_once_with("scope-test", 2.0)
        controller.verify_agent_scope.return_value = False
        with self.assertRaises(ProviderError):
            provider.provision_agent_scope("ag_other", 2)
        controller.disable_agent_scope.assert_called_once_with("scope-test")


if __name__ == "__main__":
    unittest.main()
