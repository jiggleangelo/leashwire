"""Twilio sending with an explicit deployment-owned scope controller.

A restricted API key is not itself a spending cap. The controller must provision
and verify both controls; without it, provisioning fails closed. This module
does not pretend that a usage notification is an enforceable native cap.
"""
import base64
import json
import math
import urllib.error
import urllib.parse
import urllib.request

from .base import SendResult, ProviderError


class TwilioProvider:
    name = "twilio"

    def __init__(self, sid, token, scope_controller=None):
        if not sid or not token:
            raise ValueError("Twilio account credentials are required")
        self.sid = sid
        self.token = token
        self.scope_controller = scope_controller

    def __repr__(self):
        return "<TwilioProvider credentials=masked>"

    def _controller(self):
        if self.scope_controller is None:
            raise ProviderError(
                "Twilio restricted-key and native-cap controller is required",
                code="scope_control_unavailable",
            )
        return self.scope_controller

    def provision_agent_scope(self, agent_id, daily_cap_usd):
        cap = float(daily_cap_usd)
        if not math.isfinite(cap) or cap <= 0:
            raise ValueError("daily cap must be positive and finite")
        controller = self._controller()
        ref = controller.provision_agent_scope(agent_id, cap)
        try:
            if not isinstance(ref, str) or not ref or not controller.verify_agent_scope(ref, cap):
                raise ProviderError("Twilio scope controls were not confirmed", code="cap_unconfirmed")
        except Exception:
            controller.disable_agent_scope(ref)
            raise
        return ref

    def disable_agent_scope(self, ref):
        return self._controller().disable_agent_scope(ref)

    def send(self, *, to, sender, body, ref):
        # Resolve credentials from the controller's secret store after restart.
        # Never fall back to the unrestricted parent account credentials.
        credentials = self._controller().credentials(ref)
        account_sid = credentials["account_sid"]
        key_sid = credentials["key_sid"]
        key_secret = credentials["key_secret"]
        if not account_sid or not key_sid or not key_secret:
            raise ProviderError("Twilio scope credentials unavailable")
        data = urllib.parse.urlencode({"To": to, "From": sender, "Body": body}).encode()
        url = "https://api.twilio.com/2010-04-01/Accounts/" + urllib.parse.quote(account_sid, safe="") + "/Messages.json"
        auth = base64.b64encode((key_sid + ":" + key_secret).encode()).decode()
        request = urllib.request.Request(url, data=data, headers={
            "Authorization": "Basic " + auth,
            "Content-Type": "application/x-www-form-urlencoded",
        })
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return SendResult(json.load(response)["sid"])
        except urllib.error.HTTPError as exc:
            code = None
            try:
                code = json.loads(exc.read(65536)).get("code")
            except (ValueError, TypeError, AttributeError):
                pass
            finally:
                exc.close()
            raise ProviderError("Twilio rejected request", code=code) from None

    def usage(self, ref, since):
        return self._controller().usage(ref, since)
