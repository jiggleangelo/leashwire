import importlib
import unittest
from unittest.mock import Mock

from relaygate.vault import ContactVault, InvalidContact, LocalVault, Vault


INVALID_CONTACTS = (
    None,
    4155550100,
    True,
    b"4155550100",
    [],
    {},
    "",
    "   ",
    "+",
    "() - .",
    "mail@example.com",
    "4155550100@example.com",
    "1",
    "415555010",
    "24155550100",
    "+442079460958",
    "141555501000",
    "1" * 100,
    "call4155550100",
    "4155550100 ext 1",
    "++14155550100",
    "1+4155550100",
    "４１５５５５０１００",
)


class VaultRegressionTests(unittest.TestCase):
    def setUp(self):
        self.vault = LocalVault(key=b"vault-regression-key")
        self.addCleanup(self.vault._db.close)

    def test_cli_and_server_import_and_application_build(self):
        cli = importlib.import_module("relaygate.cli")
        server = importlib.import_module("relaygate.server")
        self.assertTrue(callable(cli.main))
        self.assertTrue(callable(server.make_server))
        self.assertIs(LocalVault, Vault)
        self.assertIs(ContactVault, Vault)
        self.assertTrue(issubclass(InvalidContact, ValueError))
        app = cli.build(key=b"application-regression-key")
        self.addCleanup(app["db"].close)
        self.addCleanup(app["vault"]._db.close)
        self.assertIsInstance(app["vault"], LocalVault)

    def test_supported_phone_formats_have_same_token_and_egress(self):
        expected = "+14155550100"
        token = self.vault.identify(expected, "w")
        captured = []
        self.vault.register_egress("capture", lambda **kw: captured.append(kw["to"]))
        for contact in (
            "4155550100",
            "14155550100",
            "+14155550100",
            "(415) 555-0100",
            "+1 415 555 0100",
            "415.555.0100",
            "  +1 (415) 555-0100  ",
        ):
            with self.subTest(contact=contact):
                self.assertEqual(self.vault._normalize(contact), expected)
                self.assertEqual(self.vault.identify(contact, "w"), token)
                self.assertEqual(self.vault.persist(contact, "w"), token)
                self.vault.deliver(token, "capture")
                self.assertEqual(captured[-1], expected)
        self.assertEqual(
            self.vault._db.execute("SELECT COUNT(*) FROM vault").fetchone()[0],
            1,
        )

    def test_invalid_contacts_raise_invalid_contact_without_persistence(self):
        for contact in INVALID_CONTACTS:
            for method in (
                self.vault._normalize,
                self.vault.identify,
                self.vault.persist,
                self.vault.tokenize,
            ):
                with self.subTest(contact=contact, method=method.__name__):
                    with self.assertRaises(InvalidContact):
                        method(contact)
        self.assertEqual(
            self.vault._db.execute("SELECT COUNT(*) FROM vault").fetchone()[0],
            0,
        )

    def test_pipeline_returns_422_for_invalid_contacts_before_gate_or_send(self):
        from relaygate.pipeline import Pipeline

        db = Mock()
        keys = Mock()
        keys.authenticate.return_value = {"ws": "w", "id": "a"}
        consent = Mock()
        spend = Mock()
        audit = Mock()
        provider = Mock()
        pipeline = Pipeline(
            db, self.vault, keys, consent, spend, audit, {"fake": provider}
        )
        for contact in INVALID_CONTACTS:
            with self.subTest(contact=contact):
                result = pipeline.send("key", contact, "hello")
                self.assertFalse(result.ok)
                self.assertEqual(result.status, 422)
                self.assertEqual(result.reason, "invalid_recipient")
                self.assertIsNone(result.recipient_token)
        self.assertEqual(db.mock_calls, [])
        self.assertEqual(consent.mock_calls, [])
        self.assertEqual(spend.mock_calls, [])
        self.assertEqual(provider.mock_calls, [])
        self.assertEqual(
            self.vault._db.execute("SELECT COUNT(*) FROM vault").fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
