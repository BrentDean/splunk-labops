"""Tests for the Hetzner SSH journal collector."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "collectors"),
)

import hetzner_journal as collector


class SSHParserTests(unittest.TestCase):

    def test_successful_public_key_authentication(self):
        message = (
            "Accepted publickey for admin "
            "from 192.0.2.10 port 22 ssh2"
        )

        self.assertEqual(
            collector.classify_event(message),
            "ssh_authentication_success",
        )

        self.assertEqual(
            collector.extract_source_ip(message),
            "192.0.2.10",
        )

    def test_failed_password(self):
        message = (
            "Failed password for admin "
            "from 192.0.2.11 port 22 ssh2"
        )

        self.assertEqual(
            collector.classify_event(message),
            "ssh_authentication_failure",
        )

    def test_connection_closed_by_ip(self):
        message = (
            "Connection closed by 192.0.2.12 port 52706"
        )

        self.assertEqual(
            collector.classify_event(message),
            "ssh_connection_closed",
        )

        self.assertEqual(
            collector.extract_source_ip(message),
            "192.0.2.12",
        )

    def test_connection_reset(self):
        message = (
            "Connection reset by 192.0.2.13 port 3334"
        )

        self.assertEqual(
            collector.classify_event(message),
            "ssh_connection_reset",
        )

        self.assertEqual(
            collector.extract_source_ip(message),
            "192.0.2.13",
        )

    def test_banner_error(self):
        message = (
            "banner exchange: Connection from "
            "192.0.2.14 port 52698: invalid format"
        )

        self.assertEqual(
            collector.classify_event(message),
            "ssh_banner_error",
        )

        self.assertEqual(
            collector.extract_source_ip(message),
            "192.0.2.14",
        )

    def test_ipv6_source_address(self):
        message = (
            "Accepted publickey for admin "
            "from 2001:db8::10 port 22 ssh2"
        )

        self.assertEqual(
            collector.extract_source_ip(message),
            "2001:db8::10",
        )

    def test_invalid_source_address(self):
        self.assertIsNone(
            collector.extract_source_ip(
                "Connection closed by invalid-address port 22"
            )
        )

    def test_timestamp_preservation(self):
        record = {
            "MESSAGE": "Accepted publickey for admin",
            "__CURSOR": "test-cursor",
            "__REALTIME_TIMESTAMP": "1780000000123456",
            "_HOSTNAME": "staging-vps",
        }

        event = collector.normalize_event(record)

        self.assertAlmostEqual(
            event["time"],
            1780000000.123456,
            places=5,
        )

        self.assertEqual(
            event["index"],
            "labops_vps",
        )

        self.assertEqual(
            event["event"]["journal_cursor"],
            "test-cursor",
        )

        self.assertFalse(
            event["event"]["synthetic"]
        )

    def test_failed_submission_does_not_advance_cursor(self):
        record = {
            "MESSAGE": "Accepted publickey for admin",
            "__CURSOR": "test-cursor",
            "__REALTIME_TIMESTAMP": "1780000000123456",
            "_HOSTNAME": "staging-vps",
        }

        with (
            patch.object(
                collector,
                "retrieve_journal",
                return_value=[record],
            ),
            patch.object(
                collector,
                "submit_hec",
                side_effect=RuntimeError("HEC unavailable"),
            ),
            patch.object(
                collector,
                "save_cursor",
            ) as save_cursor,
        ):

            with self.assertRaises(RuntimeError):
                collector.main()

            save_cursor.assert_not_called()


class SSHAuthenticationDetailsTests(unittest.TestCase):

    def test_public_key_details(self):
        message = (
            "Accepted publickey for admin "
            "from 192.0.2.10 port 22 ssh2: "
            "ED25519 SHA256:ExampleFingerprint123"
        )

        details = collector.extract_auth_details(message)

        self.assertEqual(details["username"], "admin")
        self.assertEqual(details["auth_method"], "publickey")
        self.assertEqual(details["key_type"], "ED25519")
        self.assertEqual(
            details["key_fingerprint"],
            "SHA256:ExampleFingerprint123",
        )

    def test_password_authentication(self):
        message = (
            "Accepted password for admin "
            "from 192.0.2.10 port 22 ssh2"
        )

        details = collector.extract_auth_details(message)

        self.assertEqual(details["username"], "admin")
        self.assertEqual(details["auth_method"], "password")
        self.assertNotIn("key_fingerprint", details)

    def test_public_key_without_fingerprint(self):
        message = (
            "Accepted publickey for admin "
            "from 192.0.2.10 port 22 ssh2"
        )

        details = collector.extract_auth_details(message)

        self.assertEqual(details["auth_method"], "publickey")
        self.assertNotIn("key_fingerprint", details)

    def test_non_authentication_message(self):
        message = "Connection closed by 192.0.2.10 port 22"

        self.assertEqual(
            collector.extract_auth_details(message),
            {},
        )

    def test_normalized_event_contains_authentication_fields(self):
        record = {
            "MESSAGE": (
                "Accepted publickey for admin "
                "from 192.0.2.10 port 22 ssh2: "
                "ED25519 SHA256:ExampleFingerprint123"
            ),
            "__CURSOR": "synthetic-test-cursor",
            "__REALTIME_TIMESTAMP": "1780000000123456",
            "_HOSTNAME": "staging-vps",
        }

        payload = collector.normalize_event(record)
        event = payload["event"]

        self.assertEqual(
            event["event_type"],
            "ssh_authentication_success",
        )
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["auth_method"], "publickey")
        self.assertEqual(event["key_type"], "ED25519")
        self.assertEqual(
            event["key_fingerprint"],
            "SHA256:ExampleFingerprint123",
        )
        self.assertEqual(event["src_ip"], "192.0.2.10")
        self.assertFalse(event["synthetic"])


if __name__ == "__main__":
    unittest.main()
