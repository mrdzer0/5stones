import asyncio
import copy
import unittest

from backend.services.golden_corpus_service import (
    GOLDEN_CORPUS_SCHEMA_VERSION,
    GoldenCorpusError,
    evaluate_golden_corpus,
    load_golden_corpus,
    materialize_offline_reports,
    validate_golden_corpus,
)


class GoldenCorpusEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_golden_corpus()
        cls.reports = asyncio.run(materialize_offline_reports(cls.corpus))

    def test_versioned_corpus_has_positive_negative_and_blocked_labels(self):
        self.assertEqual(self.corpus["schema_version"], GOLDEN_CORPUS_SCHEMA_VERSION)
        self.assertGreaterEqual(sum(len(case["expected"]["findings"]) for case in self.corpus["cases"]), 5)
        self.assertTrue(any(not case["expected"]["findings"] for case in self.corpus["cases"]))
        self.assertTrue(any(
            test["applicability"] == "blocked"
            for case in self.corpus["cases"]
            for test in case["expected"].get("tests") or []
        ))

    def test_bundled_pipeline_passes_all_quality_gates(self):
        result = evaluate_golden_corpus(self.corpus, self.reports)

        self.assertTrue(result["gate"]["passed"])
        self.assertEqual(result["metrics"]["unsupported_finding_rate"], 0.0)
        self.assertEqual(result["metrics"]["finding_precision"], 1.0)
        self.assertEqual(result["metrics"]["finding_recall"], 1.0)
        self.assertEqual(result["metrics"]["mapping_precision"], 1.0)
        self.assertEqual(result["metrics"]["mapping_recall"], 1.0)
        self.assertEqual(result["metrics"]["test_executability_rate"], 1.0)
        self.assertEqual(result["metrics"]["blocked_test_accuracy"], 1.0)
        self.assertIn("STRIDE", result["slices"])
        self.assertIn("LINDDUN", result["slices"])
        self.assertIn("negative", result["slices"])
        self.assertEqual(len(result["evaluation_fingerprint"]), 64)

    def test_unsupported_asserted_finding_fails_precision_gate(self):
        reports = copy.deepcopy(self.reports)
        reports["documentation-omission-negative"]["threats"].append({
            "threat_id": "invented-control-gap",
            "framework": "STRIDE",
            "threat_category": "Denial of Service",
            "threat_description": "Rate limiting is absent because it was not mentioned.",
            "primary_interaction_ref": "flow-login",
            "finding_state": "grounded",
            "risk_status": "assessed",
        })

        result = evaluate_golden_corpus(self.corpus, reports)
        negative = next(item for item in result["cases"] if item["case_id"] == "documentation-omission-negative")

        self.assertFalse(result["gate"]["passed"])
        self.assertEqual(result["counters"]["unsupported_findings"], 1)
        self.assertEqual(result["counters"]["unsupported_asserted_findings"], 1)
        self.assertEqual(negative["unsupported_findings"][0]["threat_id"], "invented-control-gap")

    def test_empty_output_cannot_game_unsupported_rate(self):
        reports = {
            case["case_id"]: {"threats": [], "controls": [], "test_scenarios": []}
            for case in self.corpus["cases"]
        }

        result = evaluate_golden_corpus(self.corpus, reports)

        self.assertEqual(result["metrics"]["unsupported_finding_rate"], 0.0)
        self.assertEqual(result["metrics"]["finding_recall"], 0.0)
        self.assertFalse(result["gate"]["checks"]["finding_recall"]["passed"])
        self.assertFalse(result["gate"]["passed"])

    def test_wrong_primary_flow_reduces_mapping_precision_and_recall(self):
        reports = copy.deepcopy(self.reports)
        reports["registration-integrity"]["threats"][0]["primary_interaction_ref"] = "flow-wrong"

        result = evaluate_golden_corpus(self.corpus, reports)
        case = next(item for item in result["cases"] if item["case_id"] == "registration-integrity")

        self.assertLess(case["metrics"]["mapping_precision"], 1.0)
        self.assertLess(case["metrics"]["mapping_recall"], 1.0)
        self.assertTrue(any(edge[0] == "finding_to_flow" for edge in case["mapping_false_positives"]))

    def test_false_control_mapping_is_visible_and_fails_gate(self):
        reports = copy.deepcopy(self.reports)
        reports["registration-integrity"]["controls"].append({
            "control_id": "CAT-ctrl-004",
            "catalog_id": "ctrl-004",
            "name": "PII Data Minimization and Masking",
            "mapping_status": "mapped",
            "threat_ids": ["candidate-registration-tampering"],
        })

        result = evaluate_golden_corpus(self.corpus, reports)

        self.assertFalse(result["gate"]["checks"]["mapping_precision"]["passed"])
        case = next(item for item in result["cases"] if item["case_id"] == "registration-integrity")
        self.assertIn(
            ["control_to_finding", "ctrl-004", "G-REG-TAMPER"],
            case["mapping_false_positives"],
        )

    def test_generic_test_steps_fail_executability_gate(self):
        reports = copy.deepcopy(self.reports)
        scenario = reports["registration-integrity"]["test_scenarios"][0]
        scenario.update({
            "preconditions": "TBD",
            "steps": ["Setup test environment", "Execute attack scenario", "Verify defense"],
            "expected_result": "Works",
            "evidence_needed": [],
        })

        result = evaluate_golden_corpus(self.corpus, reports)
        case = next(item for item in result["cases"] if item["case_id"] == "registration-integrity")

        self.assertEqual(case["metrics"]["test_executability_rate"], 0.0)
        self.assertIn("generic_placeholder_steps", case["test_results"][0]["reasons"])
        self.assertFalse(result["gate"]["checks"]["test_executability_rate"]["passed"])

    def test_missing_report_and_invalid_label_contract_are_rejected(self):
        missing = copy.deepcopy(self.reports)
        missing.pop("registration-integrity")
        with self.assertRaises(GoldenCorpusError):
            evaluate_golden_corpus(self.corpus, missing)

        invalid = copy.deepcopy(self.corpus)
        invalid["cases"][0]["expected"]["findings"][0]["primary_interaction_ref"] = "not-a-flow"
        with self.assertRaises(GoldenCorpusError):
            validate_golden_corpus(invalid)


if __name__ == "__main__":
    unittest.main()
