import unittest

from tools.p0_dfd_owner_handoff import build_report


class P0DfdOwnerHandoffTests(unittest.TestCase):
    def test_handoff_preserves_open_questions_without_fabricating_owner_decisions(self):
        report = build_report({
            "schema_version": "cr8-qualification-v1",
            "mode": "fixture",
            "namespace": "run-test-dfd-handoff",
            "artifact_hash": "a" * 64,
            "cases": [{
                "case_id": "case-a",
                "source_file": "sample.md",
                "run_status": "completed_with_warnings",
                "signoff_ready": False,
                "metrics": {"topology_validity": {"numerator": 2, "denominator": 3}},
                "observed": {"dfd_nodes": 3, "dfd_flows": 1, "dfd_validation": {
                    "readiness": "not_ready",
                    "topology": "partial",
                    "topology_issues": ["Node Service has no evidenced flow."],
                    "knowledge_issues": ["Classification is incomplete."],
                    "blocking_reasons": ["Question question-1 is open."],
                    "open_questions": [{
                        "id": "question-1",
                        "status": "open",
                        "question": "Provide an observed trace for this interaction.",
                        "affected_refs": ["entity-service"],
                    }],
                    "semantic_quality": {"counts": {"nodes": 3, "flows": 1, "zones": 1, "isolated_nodes": 1}},
                }},
            }],
        })

        self.assertIn("not an architecture decision", report)
        self.assertIn("2/3 (66.67%)", report)
        self.assertIn("Provide an observed trace for this interaction.", report)
        self.assertIn("Owner: **pending**", report)
        self.assertIn("Decision: **pending**", report)
        self.assertIn("Affected references: `entity-service`", report)
        self.assertIn("1/1", report)

    def test_rejects_unsupported_qualification_schema(self):
        with self.assertRaises(ValueError):
            build_report({"schema_version": "legacy", "cases": [{}]})

    def test_rejects_qualification_without_cases(self):
        with self.assertRaises(ValueError):
            build_report({"schema_version": "cr8-qualification-v1", "cases": []})


if __name__ == "__main__":
    unittest.main()
