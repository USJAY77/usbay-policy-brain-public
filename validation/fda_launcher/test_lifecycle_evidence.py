#!/usr/bin/env python3
"""Isolated tests for lifecycle evidence allocation; no workers are started."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_validation as target


def proven(case):
    return {
        "case": case,
        "execution_state": "EXECUTED",
        "containment_ok": True,
        "worker_reaped": True,
        "cleanup_state": "PROVEN",
        "worker_group_absent": True,
        "child_groups_absent": True,
        "cleanup_errors": [],
        "cleanup_deadline_started": True,
        "cleanup_start_monotonic": 10.0,
        "cleanup_deadline_monotonic": 13.0,
        "cleanup_complete_monotonic": 12.0,
        "cleanup_elapsed_seconds": 2.0,
        "remaining_owned_groups": [],
        "malformed_ownership_records": [],
        "assertion_failures": [],
        "watchdog": "exited",
    }


class LifecycleEvidenceTests(unittest.TestCase):
    def test_historical_directory_does_not_block_new_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical = root / "missing_cases_batch"
            historical.mkdir()
            marker = historical / "historical.txt"
            marker.write_bytes(b"immutable-history")

            attempt = target.create_attempt_directory(
                root, "20260919T120000Z", "a" * 32
            )

            self.assertNotEqual(attempt, historical)
            self.assertTrue(attempt.is_dir())
            self.assertEqual(marker.read_bytes(), b"immutable-history")

    def test_two_attempts_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = target.create_attempt_directory(
                root, "20260919T120000Z", "a" * 32
            )
            second = target.create_attempt_directory(
                root, "20260919T120000Z", "b" * 32
            )
            self.assertNotEqual(first, second)
            self.assertTrue(first.is_dir())
            self.assertTrue(second.is_dir())

    def test_forced_collision_fails_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attempt = target.create_attempt_directory(
                root, "20260919T120000Z", "a" * 32
            )
            marker = attempt / "preserved.bin"
            marker.write_bytes(b"preserve-me")

            with self.assertRaises(FileExistsError):
                target.create_attempt_directory(
                    root, "20260919T120000Z", "a" * 32
                )

            self.assertEqual(marker.read_bytes(), b"preserve-me")

    def test_non_execution_dispatch_has_no_filesystem_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []

            handlers = {
                "help_fn": lambda: calls.append("help"),
                "scheduler_test_fn": lambda: calls.append("self-test"),
                "worker_fn": lambda *args: self.fail("worker dispatched"),
                "main_fn": lambda: self.fail("main dispatched"),
            }
            target.dispatch_argv(["--help"], **handlers)
            target.dispatch_argv(["--scheduler-self-test"], **handlers)
            with self.assertRaises(SystemExit):
                target.dispatch_argv(["--malformed"], **handlers)

            self.assertEqual(calls, ["help", "self-test"])
            self.assertEqual(list(root.iterdir()), [])

    def test_execution_dispatch_allocates_only_through_main(self):
        calls = []
        target.dispatch_argv(
            [],
            help_fn=lambda: self.fail("help dispatched"),
            scheduler_test_fn=lambda: self.fail("self-test dispatched"),
            worker_fn=lambda *args: self.fail("worker dispatched"),
            main_fn=lambda: calls.append("main"),
        )
        self.assertEqual(calls, ["main"])

    def test_case_files_use_selected_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = target.create_attempt_directory(
                root, "20260919T120000Z", "a" * 32
            )
            paths = target.prepare_case_files(
                "term-to-kill", selected, "nonce"
            )
            self.assertTrue(all(path.parent == selected for path in paths))
            self.assertTrue(all(path.exists() for path in paths))
            self.assertEqual(
                sorted(path.name for path in selected.iterdir()),
                sorted(path.name for path in paths),
            )

    def test_containment_failure_stops_bound_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            selected = Path(temporary)
            calls = []

            def injected(case, evidence_dir):
                calls.append((case, evidence_dir))
                result = proven(case)
                result["containment_ok"] = False
                return result

            results = target.schedule_cases(
                lambda case: injected(case, selected),
                ("first", "second"),
            )

            self.assertEqual(calls, [("first", selected)])
            self.assertEqual(
                [item["execution_state"] for item in results],
                ["EXECUTED", "NOT_EXECUTED"],
            )

    def test_main_records_selected_temporary_destination_and_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical = root / "missing_cases_batch"
            historical.mkdir()
            historical_marker = historical / "historical.bin"
            historical_marker.write_bytes(b"unchanged")
            calls = []

            def attempt_factory(evidence_root):
                self.assertEqual(Path(evidence_root), root)
                return target.create_attempt_directory(
                    evidence_root, "20260919T120000Z", "a" * 32
                )

            def injected(case, evidence_dir):
                calls.append((case, evidence_dir))
                result = proven(case)
                result["containment_ok"] = False
                return result

            def fake_digest(path):
                if path == target.LAUNCHER:
                    return target.EXPECTED_LAUNCHER
                if path == target.PROPOSAL:
                    return target.EXPECTED_PROPOSAL
                return "stable-source-hash"

            extracted = (
                "# isolated extracted source\n",
                {
                    "TERM_WAIT_SECONDS": target.TERM_GRACE_SECONDS,
                    "KILL_WAIT_SECONDS": target.KILL_GRACE_SECONDS,
                },
                ["isolated"],
                "isolated-extraction-hash",
            )
            with mock.patch.object(target, "digest", side_effect=fake_digest), \
                    mock.patch.object(target, "extract_source",
                                      return_value=extracted):
                with self.assertRaisesRegex(
                        SystemExit, "validation assertions failed"):
                    target.main(
                        evidence_root=root,
                        attempt_factory=attempt_factory,
                        case_runner=injected,
                    )

            attempts = [
                path for path in root.iterdir()
                if path.name.startswith("missing_cases_")
                and path.name != "missing_cases_batch"
            ]
            self.assertEqual(len(attempts), 1)
            attempt = attempts[0]
            raw = json.loads((attempt / "raw.json").read_text())
            self.assertEqual(raw["attempt_directory"], str(attempt))
            self.assertTrue(
                all(item["attempt_directory"] == str(attempt)
                    for item in raw["cases"])
            )
            self.assertEqual(
                calls, [(target.MISSING_CASES[0], attempt)]
            )
            self.assertEqual(
                [item["execution_state"] for item in raw["cases"]],
                ["EXECUTED"] + ["NOT_EXECUTED"] * 6,
            )
            self.assertTrue(
                (attempt / "extracted_supervisor_source.py").is_file()
            )
            self.assertEqual(historical_marker.read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()