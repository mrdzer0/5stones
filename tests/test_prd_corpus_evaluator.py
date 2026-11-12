import copy
import json
import unittest
from pathlib import Path

from backend.services.prd_corpus_evaluator import (
    CONTRACT_SCHEMA_VERSION,
    DEFAULT_CONTRACT_PATH,
    DEFAULT_MANIFEST_PATH,
    DEFAULT_RESULTS_PATH,
    EVALUATOR_VERSION,
    PRDCorpusEvaluationError,
    _aggregate_explicit_metric,
    _explicit_metric,
    evaluate_prd_corpus,
    render_markdown,
    validate_metric_contract,
    validate_result_payload,
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class PRDCorpusEvaluatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = _load(DEFAULT_RESULTS_PATH)
        cls.manifest = _load(DEFAULT_MANIFEST_PATH)
        cls.contract = _load(DEFAULT_CONTRACT_PATH)

    def test_contract_is_versioned_and_contains_all_required_metrics(self):
        validate_metric_contract(self.contract)
        self.assertEqual(self.contract["schema_version"], CONTRACT_SCHEMA_VERSION)
        self.assertEqual(self.contract["evaluator_version"], EVALUATOR_VERSION)
        self.assertEqual(self.contract["corpus_result_schema_version"], "prd-corpus-e2e-v2")
        self.assertIn("prd-corpus-e2e-v1", self.contract["accepted_legacy_result_schema_versions"])
        self.assertEqual(len(self.contract["required_provenance"]), 11)

    def test_baseline_fails_closed_for_framework_and_unmeasured_metrics(self):
        evaluation = evaluate_prd_corpus(self.results, self.manifest, self.contract)

        self.assertFalse(evaluation["gate"]["passed"])
        self.assertTrue(evaluation["gate"]["fail_closed"])
        self.assertTrue(evaluation["legacy_input"])
        self.assertEqual(evaluation["target_result_schema_version"], "prd-corpus-e2e-v2")
        self.assertEqual(evaluation["case_count"], 9)
        self.assertEqual(evaluation["metrics"]["framework_validation"]["numerator"], 0)
        self.assertEqual(evaluation["metrics"]["framework_validation"]["denominator"], 9)
        self.assertEqual(evaluation["metrics"]["framework_validation"]["status"], "legacy_derived")
        self.assertFalse(evaluation["gate"]["checks"]["framework_validation"]["passed"])
        self.assertFalse(evaluation["gate"]["checks"]["dfd_precision"]["passed"])

    def test_legacy_percentage_never_becomes_quality_metric_without_counts(self):
        evaluation = evaluate_prd_corpus(self.results, self.manifest, self.contract)

        coverage = evaluation["metrics"]["ingestion_coverage"]
        recall = evaluation["metrics"]["dfd_entity_recall"]
        self.assertIsNone(coverage["value"])
        self.assertIsNone(coverage["numerator"])
        self.assertIsNone(coverage["denominator"])
        self.assertEqual(coverage["status"], "legacy_reported_only")
        self.assertIsNone(recall["value"])
        self.assertFalse(coverage["eligible_for_gate"])

    def test_diagnostic_counts_marked_ineligible_cannot_satisfy_release_metric(self):
        diagnostic_metrics = (
            "dfd_precision", "finding_precision", "finding_recall", "deferred_recall",
            "control_mapping_precision", "control_mapping_recall", "test_executability",
        )
        for metric_name in diagnostic_metrics:
            with self.subTest(metric=metric_name):
                case = {"metrics": {metric_name: {
                    "numerator": 307,
                    "denominator": 307,
                    "eligible_for_gate": False,
                    "reason": "Structural proxy; independent labels are missing.",
                }}}
                measured = _explicit_metric(case, metric_name)
                aggregate = _aggregate_explicit_metric([case], metric_name)

                self.assertEqual(measured["status"], "not_measured")
                self.assertEqual(measured["numerator"], 307)
                self.assertIsNone(measured["value"])
                self.assertFalse(measured["eligible_for_gate"])
                self.assertEqual(aggregate["status"], "not_measured")
                self.assertFalse(aggregate["eligible_for_gate"])

    def test_fingerprint_is_stable_and_excludes_evaluation_time(self):
        first = evaluate_prd_corpus(self.results, self.manifest, self.contract)
        changed = copy.deepcopy(self.results)
        changed["evaluated_at"] = "different-runtime-time"
        second = evaluate_prd_corpus(changed, self.manifest, self.contract)

        self.assertEqual(first["evaluation_fingerprint"], second["evaluation_fingerprint"])
        self.assertEqual(first["source_artifacts"]["results_hash"], second["source_artifacts"]["results_hash"])

    def test_provenance_reports_safe_missing_fields_without_source_text(self):
        evaluation = evaluate_prd_corpus(self.results, self.manifest, self.contract)

        self.assertEqual(evaluation["provenance"]["cases_with_provider_metadata"], 0)
        first = evaluation["provenance"]["cases"][0]
        self.assertIn("run_id", first["missing_fields"])
        self.assertIn("dfd_revision", first["missing_fields"])
        self.assertTrue(first["source_file_exists"])
        self.assertNotIn("safe_content", json.dumps(evaluation))

    def test_markdown_discloses_denominator_and_fail_closed_reason(self):
        evaluation = evaluate_prd_corpus(self.results, self.manifest, self.contract)
        markdown = render_markdown(evaluation)

        self.assertIn("FAIL", markdown)
        self.assertIn("0/9", markdown)
        self.assertIn("legacy 95.89% (no counts)", markdown)
        self.assertIn("not measured", markdown)
        self.assertIn("fail-closed", markdown)

    def test_result_contract_rejects_duplicate_cases(self):
        invalid = copy.deepcopy(self.results)
        invalid["cases"].append(copy.deepcopy(invalid["cases"][0]))
        with self.assertRaises(PRDCorpusEvaluationError):
            validate_result_payload(invalid)

    def test_v2_result_requires_provenance_and_explicit_metric_counts(self):
        upgraded = copy.deepcopy(self.results)
        upgraded["schema_version"] = "prd-corpus-e2e-v2"
        with self.assertRaises(PRDCorpusEvaluationError):
            validate_result_payload(upgraded)


if __name__ == "__main__":
    unittest.main()
