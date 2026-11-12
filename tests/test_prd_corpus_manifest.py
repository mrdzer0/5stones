"""Structural validation for the synthetic PRD threat-modeling corpus."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


CORPUS_DIR = Path(__file__).parent / "prd_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


class PrdCorpusManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.cases = cls.manifest["cases"]

    def test_manifest_has_all_completeness_bands_and_multiple_domains(self):
        self.assertEqual(
            {case["completeness"] for case in self.cases},
            {"complete", "half", "incomplete"},
        )
        self.assertGreaterEqual(len({case["domain"] for case in self.cases}), 7)
        self.assertGreaterEqual(len(self.cases), 8)

    def test_every_case_is_readable_and_has_metadata(self):
        ids = set()
        for case in self.cases:
            self.assertNotIn(case["id"], ids)
            ids.add(case["id"])
            path = CORPUS_DIR / case["file"]
            self.assertTrue(path.is_file(), case["file"])
            content = path.read_text(encoding="utf-8")
            self.assertGreater(len(content), 1000, case["file"])
            self.assertIn("# Product Requirements Document", content)
            self.assertRegex(content, r"(?m)^> ID:")
            self.assertRegex(content, r"(?m)^> Completeness:")
            self.assertRegex(content, r"(?m)^> Product type:")
            self.assertIn("## Actors and roles", content)
            self.assertIn("## User journeys", content)
            self.assertIn("## Data inventory", content)
            self.assertIn("## External systems", content)
            self.assertIn("## Acceptance criteria", content)

    def test_complete_cases_have_explicit_model_sections(self):
        for case in self.cases:
            if case["completeness"] != "complete":
                continue
            content = (CORPUS_DIR / case["file"]).read_text(encoding="utf-8")
            self.assertIn("## Components and trust boundaries", content)
            self.assertIn("## Security and privacy requirements", content)
            self.assertIn("## Data flows", content)

    def test_half_and_incomplete_cases_expose_uncertainty(self):
        for case in self.cases:
            if case["completeness"] not in {"half", "incomplete"}:
                continue
            content = (CORPUS_DIR / case["file"]).read_text(encoding="utf-8")
            self.assertRegex(
                content,
                r"(?i)(open questions|tbd|unknown|not defined|out of scope|assumption)",
                case["file"],
            )

    def test_manifest_expected_sections_are_non_empty(self):
        required = {
            "must_detect_actors",
            "must_detect_components",
            "must_surface_topics",
            "must_not_invent",
            "expected_deferred_topics",
        }
        for case in self.cases:
            expected = case["expected"]
            self.assertTrue(required.issubset(expected), case["id"])
            for key in required:
                self.assertTrue(expected[key], f"{case['id']}:{key}")


if __name__ == "__main__":
    unittest.main()
