"""Telnyx transport. Live account behavior still requires sandbox validation."""
import json
import math
import urllib.error
import urllib.parse
import urllib.request

from .base import SendResult, ProviderError


class TelnyxProvider:
    name = "telnyx"

    def __init__(self, api_key):
        if not api_key:
            raise ValueError("Telnyx API key is required")
        self.key = api_key

    def __repr__(self):
        return "<TelnyxProvider credentials=masked>"

    def _call(self, path, payload=None, method="POST"):
        request = urllib.request.Request(
            "https://api.telnyx.com/v2" + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            code = None
            try:
                errors = json.loads(exc.read(65536)).get("errors", [])
                if errors:
                    code = errors[0].get("code")
            except (ValueError, TypeError, AttributeError):
                pass
            finally:
                exc.close()
            raise ProviderError("Telnyx rejected request", code=code) from None
        # Transport failures deliberately propagate: acceptance is unknown and
        # Pipeline must retain the pessimistic reservation.

    def provision_agent_scope(self, agent_id, daily_cap_usd):
        cap = float(daily_cap_usd)
        if not math.isfinite(cap) or cap <= 0:
            raise ValueError("daily cap must be positive and finite")
        data = self._call("/messaging_profiles", {
            "name": "relaygate-" + agent_id,
            "enabled": False,
            "daily_spend_limit": str(cap),
            "daily_spend_limit_enabled": True,
        })["data"]
        ref = data["id"]
        path = "/messaging_profiles/" + urllib.parse.quote(ref, safe="")
        # Read back the cap before enabling the new profile. A missing or
        # ignored cap leaves the profile disabled and prevents local activation.
        verified = self._call(path, method="GET")["data"]
        try:
            installed = float(verified["daily_spend_limit"])
            valid = (verified["daily_spend_limit_enabled"] is True
                     and math.isfinite(installed) and 0 < installed <= cap)
        except (KeyError, TypeError, ValueError):
            valid = False
        if not valid:
            raise ProviderError("Telnyx native cap was not confirmed", code="cap_unconfirmed")
        self._call(path, {"enabled": True}, method="PATCH")
        return ref

    def disable_agent_scope(self, ref):
        self._call("/messaging_profiles/" + urllib.parse.quote(ref, safe=""),
                   {"enabled": False}, method="PATCH")
        return True

    def send(self, *, to, sender, body, ref):
        data = self._call("/messages", {
            "to": to, "from": sender, "text": body, "messaging_profile_id": ref,
        })["data"]
        return SendResult(data["id"])

    def usage(self, ref, since):
        # Never report an unimplemented live reconciliation as zero usage.
        raise ProviderError("Telnyx live usage reconciliation is not implemented",
                            code="usage_unavailable")
