import hashlib
import hmac
import os
import re
import sqlite3
import threading


class InvalidContact(ValueError):
    """The contact is not a supported US phone number."""


class Vault:
    """Encrypted contact storage with registered egress as its only plaintext API."""

    def __init__(self, path=":memory:", key=None):
        self._lock = threading.RLock()
        if str(path) != ":memory:":
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS vault (token TEXT PRIMARY KEY, sealed BLOB NOT NULL)")
        self._db.commit()
        if key is None:
            key = os.urandom(32)
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._key_material = hashlib.sha256(bytes(key)).digest()
        self._egress = {}

    def __repr__(self):
        return "<Vault sealed>"

    @staticmethod
    def _normalize(contact):
        if not isinstance(contact, str):
            raise InvalidContact("contact must be a string")
        contact = contact.strip()
        if not re.fullmatch(r"\+?[0-9 ().-]+", contact):
            raise InvalidContact("contact must be a US phone number")
        digits = re.sub(r"[^0-9]", "", contact)
        if len(digits) == 10:
            digits = "1" + digits
        elif len(digits) != 11 or not digits.startswith("1"):
            raise InvalidContact("contact must have 10 digits or 11 starting with 1")
        return "+" + digits

    def _derive(self, purpose):
        return hmac.new(self._key_material, purpose.encode("ascii"), hashlib.sha256).digest()

    @staticmethod
    def _stream(key, nonce, length):
        if length < 0:
            raise ValueError("invalid stream length")
        chunks = []
        remaining = length
        counter = 0
        while remaining:
            block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            chunk = block[:remaining]
            chunks.append(chunk)
            remaining -= len(chunk)
            counter += 1
        return b"".join(chunks)

    def _seal(self, plain):
        if isinstance(plain, str):
            plain = plain.encode("utf-8")
        elif isinstance(plain, bytearray):
            plain = bytes(plain)
        elif not isinstance(plain, bytes):
            raise TypeError("plaintext must be str or bytes")
        key = self._derive("vault-encryption")
        nonce = os.urandom(16)
        stream = self._stream(key, nonce, len(plain))
        cipher = bytes(a ^ b for a, b in zip(plain, stream))
        tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        return nonce + tag + cipher

    def _unseal(self, sealed):
        sealed = bytes(sealed)
        if len(sealed) < 48:
            raise ValueError("invalid vault record")
        nonce, tag, cipher = sealed[:16], sealed[16:48], sealed[48:]
        key = self._derive("vault-encryption")
        expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("vault record authentication failed")
        stream = self._stream(key, nonce, len(cipher))
        return bytes(a ^ b for a, b in zip(cipher, stream)).decode("utf-8")

    def identify(self, contact, workspace=""):
        normalized = self._normalize(contact)
        workspace = "" if workspace is None else str(workspace)
        message = workspace.encode("utf-8") + b"\0" + normalized.encode("utf-8")
        digest = hmac.new(self._derive("recipient-token"), message, hashlib.sha256).hexdigest()[:32]
        return "rc_" + digest

    def persist(self, contact, workspace=""):
        normalized = self._normalize(contact)
        token = self.identify(normalized, workspace)
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO vault(token, sealed) VALUES(?, ?)", (token, self._seal(normalized)))
            self._db.commit()
        return token

    def tokenize(self, contact, workspace=""):
        return self.persist(contact, workspace)

    def register_egress(self, provider, sender):
        if not callable(sender):
            raise TypeError("sender must be callable")
        with self._lock:
            self._egress[provider] = sender

    def deliver(self, token, provider, **kwargs):
        with self._lock:
            row = self._db.execute("SELECT sealed FROM vault WHERE token=?", (token,)).fetchone()
            if row is None:
                raise KeyError(token)
            if provider not in self._egress:
                raise KeyError("unregistered egress provider")
            return self._egress[provider](to=self._unseal(row[0]), **kwargs)

    def forget(self, token):
        with self._lock:
            self._db.execute("DELETE FROM vault WHERE token=?", (token,))
            self._db.commit()


LocalVault = Vault
ContactVault = Vault
