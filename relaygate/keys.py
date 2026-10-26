import hashlib
import hmac
import secrets

from .audit import IDENTIFIERS


class AuthError(Exception):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason


class KeyStore:
    def __init__(self, db, providers):
        self.db = db
        self.providers = providers

    def _digest(self, key, salt):
        digest = hashlib.pbkdf2_hmac("sha256", key.encode(), bytes.fromhex(salt), 100000)
        return "pbkdf2_sha256$100000$" + digest.hex()

    def provision_agent(self, ws, name, provider, caps, scopes=("messages:send",), handler_kind="langchain", handler_url="", sender=""):
        if not isinstance(ws, str) or not IDENTIFIERS["workspace"].fullmatch(ws):
            raise ValueError("invalid workspace identifier")
        if not self.db.execute("SELECT 1 FROM workspaces WHERE id=?", (ws,)).fetchone():
            raise ValueError("unknown workspace")
        agent_id = "ag_" + secrets.token_hex(6)
        api_key = f"ak_live_{agent_id}_{secrets.token_hex(16)}"
        salt = secrets.token_hex(32)
        digest = self._digest(api_key, salt)
        ref = self.providers[provider].provision_agent_scope(agent_id, float(caps[0]))
        self.db.execute(
            "INSERT INTO agents(id,ws,name,provider,provider_ref,key_hash,key_salt,scopes,status,cap_daily_usd,cap_monthly_usd,handler_kind,handler_url,sender) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (agent_id, ws, name, provider, ref, digest, salt, " ".join(scopes), "active", float(caps[0]), float(caps[1]), handler_kind, handler_url, sender),
        )
        self.db.commit()
        return agent_id, api_key

    def authenticate(self, key, scope):
        if not isinstance(key, str) or len(key) > 128 or not key.startswith("ak_live_ag_"):
            raise AuthError(401, "invalid_key")
        try:
            agent_id, secret = key.removeprefix("ak_live_").rsplit("_", 1)
            if not IDENTIFIERS["agent_id"].fullmatch(agent_id) or len(secret) != 32:
                raise ValueError
            bytes.fromhex(secret)
        except ValueError:
            raise AuthError(401, "invalid_key") from None
        row = self.db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not row:
            raise AuthError(401, "invalid_key")
        stored = row["key_hash"]
        legacy = not stored.startswith("pbkdf2_sha256$")
        digest = (hmac.new(bytes.fromhex(row["key_salt"]), key.encode(), hashlib.sha256).hexdigest()
                  if legacy else self._digest(key, row["key_salt"]))
        if not hmac.compare_digest(digest, stored):
            raise AuthError(401, "invalid_key")
        if legacy:
            self.db.execute("UPDATE agents SET key_hash=? WHERE id=?", (self._digest(key, row["key_salt"]), agent_id))
            self.db.commit()
        if row["status"] != "active":
            raise AuthError(423, "agent_suspended")
        if scope not in row["scopes"].split():
            raise AuthError(403, "wrong_scope")
        return row

    def status(self, agent_id, status):
        if status not in {"active", "suspended_cap", "suspended_manual"}:
            raise ValueError("invalid status")
        cur = self.db.execute("UPDATE agents SET status=? WHERE id=?", (status, agent_id))
        self.db.commit()
        if not cur.rowcount:
            raise KeyError("unknown agent")
