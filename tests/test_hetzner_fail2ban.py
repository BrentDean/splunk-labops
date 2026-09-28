"""Tests for the Hetzner Fail2Ban log collector."""

import base64
import json
import sys
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch


sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "collectors"),
)

import hetzner_fail2ban as collector


def log_line(message, level="INFO"):
    return (
        "2026-09-26 01:30:00,123 "
        "fail2ban.actions [868]: "
        f"{level} {message}\n"
    )


def make_snapshot(identity, content):
    return {
        "identity": identity,
        "data": base64.b64encode(
            content.encode()
        ).decode(),
    }


class Fail2BanParserTests(unittest.TestCase):

    def test_ban_event(self):
        event = collector.normalize_line(
            log_line("[sshd] Ban 192.0.2.10").strip()
        )

        self.assertEqual(
            event["event"]["event_type"],
            "fail2ban_ban",
        )

        self.assertEqual(
            event["event"]["src_ip"],
            "192.0.2.10",
        )

        self.assertEqual(
            event["event"]["jail"],
            "sshd",
        )

    def test_unban_event(self):
        event = collector.normalize_line(
            log_line("[sshd] Unban 192.0.2.10").strip()
        )

        self.assertEqual(
            event["event"]["event_type"],
            "fail2ban_unban",
        )

    def test_failure_detected(self):
        event = collector.normalize_line(
            log_line("[sshd] Found 192.0.2.10").strip()
        )

        self.assertEqual(
            event["event"]["event_type"],
            "fail2ban_failure_detected",
        )

    def test_rollover_event(self):
        event = collector.normalize_line(
            log_line(
                "rollover performed on /var/log/fail2ban.log"
            ).strip()
        )

        self.assertEqual(
            event["event"]["event_type"],
            "fail2ban_log_rollover",
        )

    def test_error_event(self):
        event = collector.normalize_line(
            log_line(
                "Unable to initialize jail",
                level="ERROR",
            ).strip()
        )

        self.assertEqual(
            event["event"]["event_type"],
            "fail2ban_error",
        )

    def test_original_timestamp(self):
        event = collector.normalize_line(
            log_line("[sshd] Ban 192.0.2.10").strip()
        )

        self.assertEqual(
            event["time"],
            1790386200.123,
        )

        self.assertEqual(
            event["index"],
            "labops_vps",
        )

        self.assertEqual(
            event["source"],
            "fail2ban:log",
        )

        self.assertFalse(
            event["event"]["synthetic"]
        )

    def test_invalid_log_format(self):
        with self.assertRaises(ValueError):
            collector.normalize_line(
                "This is not a Fail2Ban log entry"
            )


class Fail2BanCollectionTests(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()

        self.addCleanup(
            self.directory.cleanup
        )

        self.state_file = (
            Path(self.directory.name)
            / "fail2ban-state.json"
        )

        state_patch = patch.object(
            collector,
            "STATE_FILE",
            self.state_file,
        )

        state_patch.start()

        self.addCleanup(
            state_patch.stop
        )

    def test_initial_collection(self):
        snapshot = make_snapshot(
            "device:100",
            log_line("[sshd] Ban 192.0.2.10"),
        )

        with (
            patch.object(
                collector,
                "retrieve_snapshot",
                return_value={
                    "current": snapshot,
                    "previous": None,
                },
            ),
            patch.object(
                collector.shared,
                "submit_hec",
            ) as submit,
        ):
            collector.main()

            submit.assert_called_once()

        state = collector.read_state()

        self.assertEqual(
            state["identity"],
            "device:100",
        )

        self.assertEqual(
            state["offset"],
            len(
                log_line(
                    "[sshd] Ban 192.0.2.10"
                ).encode()
            ),
        )

    def test_second_collection_has_no_duplicates(self):
        content = log_line(
            "[sshd] Ban 192.0.2.10"
        )

        snapshot = make_snapshot(
            "device:100",
            content,
        )

        collector.save_state(
            "device:100",
            len(content.encode()),
        )

        with (
            patch.object(
                collector,
                "retrieve_snapshot",
                return_value={
                    "current": snapshot,
                    "previous": None,
                },
            ),
            patch.object(
                collector.shared,
                "submit_hec",
            ) as submit,
        ):
            collector.main()

            submit.assert_not_called()

    def test_failed_submission_preserves_offset(self):
        content = log_line(
            "[sshd] Ban 192.0.2.10"
        )

        snapshot = make_snapshot(
            "device:100",
            content,
        )

        with (
            patch.object(
                collector,
                "retrieve_snapshot",
                return_value={
                    "current": snapshot,
                    "previous": None,
                },
            ),
            patch.object(
                collector.shared,
                "submit_hec",
                side_effect=RuntimeError(
                    "HEC unavailable"
                ),
            ),
        ):
            with self.assertRaises(RuntimeError):
                collector.main()

        state = collector.read_state()

        self.assertEqual(
            state["offset"],
            0,
        )

    def test_rotation_collects_previous_then_current(self):
        old_content = (
            log_line(
                "[sshd] Ban 192.0.2.10"
            )
            +
            log_line(
                "[sshd] Unban 192.0.2.10"
            )
        )

        new_content = log_line(
            "[sshd] Ban 192.0.2.11"
        )

        first_line_length = len(
            log_line(
                "[sshd] Ban 192.0.2.10"
            ).encode()
        )

        collector.save_state(
            "device:100",
            first_line_length,
        )

        with (
            patch.object(
                collector,
                "retrieve_snapshot",
                return_value={
                    "previous": make_snapshot(
                        "device:100",
                        old_content,
                    ),
                    "current": make_snapshot(
                        "device:101",
                        new_content,
                    ),
                },
            ),
            patch.object(
                collector.shared,
                "submit_hec",
            ) as submit,
        ):
            collector.main()

            self.assertEqual(
                submit.call_count,
                2,
            )

        state = collector.read_state()

        self.assertEqual(
            state["identity"],
            "device:101",
        )

        self.assertEqual(
            state["offset"],
            len(new_content.encode()),
        )

    def test_missing_rotated_file_stops_collection(self):
        collector.save_state(
            "device:100",
            50,
        )

        with patch.object(
            collector,
            "retrieve_snapshot",
            return_value={
                "current": make_snapshot(
                    "device:101",
                    log_line(
                        "[sshd] Ban 192.0.2.10"
                    ),
                ),
                "previous": None,
            },
        ):
            with self.assertRaises(RuntimeError):
                collector.main()

        self.assertEqual(
            collector.read_state()["identity"],
            "device:100",
        )

    def test_truncated_log_stops_collection(self):
        snapshot = {
            "identity": "device:100",
            "data": b"short",
        }

        with self.assertRaises(RuntimeError):
            collector.process_file(
                snapshot,
                offset=100,
            )

    def test_incomplete_line_is_not_submitted(self):
        snapshot = {
            "identity": "device:100",
            "data": log_line(
                "[sshd] Ban 192.0.2.10"
            ).rstrip("\n").encode(),
        }

        with patch.object(
            collector.shared,
            "submit_hec",
        ) as submit:
            accepted = collector.process_file(
                snapshot,
                offset=0,
            )

            self.assertEqual(
                accepted,
                0,
            )

            submit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
