#!/usr/bin/env python3
"""Render unresolved per-case DFD evidence into an owner review handoff."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _text(value: Any, fallback: str = "not recorded") -> str:
    if value is None:
        return fallback
    return str(value).replace("\r", " ").replace("\n", " ").strip() or fallback


def _items(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def _quote(value: str) -> str:
    return "\n".join(f"> {line}" for line in value.splitlines())


def build_report(qualification: dict[str, Any]) -> str:
    if qualification.get("schema_version") != "cr8-qualification-v1":
        raise ValueError("qualification must use cr8-qualification-v1")
    cases = qualification.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("qualification must contain at least one case")

    totals = {"topology_numerator": 0, "topology_denominator": 0, "open_questions": 0, "not_ready_cases": 0}
    prepared: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        observed = case.get("observed") if isinstance(case.get("observed"), dict) else {}
        validation = observed.get("dfd_validation") if isinstance(observed.get("dfd_validation"), dict) else {}
        metric = case.get("metrics", {}).get("topology_validity", {}) if isinstance(case.get("metrics"), dict) else {}
        numerator = metric.get("numerator") if isinstance(metric, dict) else None
        denominator = metric.get("denominator") if isinstance(metric, dict) else None
        if isinstance(numerator, int) and isinstance(denominator, int):
            totals["topology_numerator"] += numerator
            totals["topology_denominator"] += denominator
        questions = validation.get("open_questions", [])
        if isinstance(questions, list):
            totals["open_questions"] += len(questions)
        if validation.get("readiness") != "ready":
            totals["not_ready_cases"] += 1
        prepared.append((case, validation, metric if isinstance(metric, dict) else {}))

    mode = _text(qualification.get("mode"), "unknown")
    run_id = _text(qualification.get("namespace"), "unknown")
    artifact_hash = _text(qualification.get("artifact_hash"), "missing")
    ratio = (
        f"{totals['topology_numerator']}/{totals['topology_denominator']} "
        f"({totals['topology_numerator'] / totals['topology_denominator']:.2%})"
        if totals["topology_denominator"] else "not measured"
    )
    lines = [
        "# DFD Owner Review Handoff",
        "",
        f"- Qualification run: `{run_id}`",
        f"- Mode: **{mode}**",
        f"- Qualification artifact hash: `{artifact_hash}`",
        f"- Cases: {len(prepared)}; not ready: {totals['not_ready_cases']}/{len(prepared)}",
        f"- Aggregate structural topology checks: **{ratio}**",
        f"- Open DFD questions: **{totals['open_questions']}**",
        "",
        "> This report is a review handoff, not an architecture decision. It preserves unresolved questions from the qualification artifact and leaves all owner decisions blank. Fixture-mode results are synthetic contract evidence and must not be treated as a live architecture or provider-quality assessment.",
        "",
        "## Owner review instructions",
        "",
        "For each issue, record the responsible product/architecture owner, the evidence locator or observed trace, the decision, and its rationale in the authenticated DFD review workflow. Valid outcomes include evidence-backed flow correction, evidence-backed scope removal, or an owned deferred decision. Do not close a blocker by editing this report.",
        "",
    ]

    for case, validation, metric in prepared:
        case_id = _text(case.get("case_id"), "unknown-case")
        source_file = _text(case.get("source_file"), "not recorded")
        observed = case.get("observed") if isinstance(case.get("observed"), dict) else {}
        semantic = validation.get("semantic_quality") if isinstance(validation.get("semantic_quality"), dict) else {}
        counts = semantic.get("counts") if isinstance(semantic.get("counts"), dict) else {}
        numerator, denominator = metric.get("numerator"), metric.get("denominator")
        topology = f"{numerator}/{denominator}" if isinstance(numerator, int) and isinstance(denominator, int) else "not measured"
        questions = validation.get("open_questions", [])
        topology_issues = _items(validation.get("topology_issues"))
        knowledge_issues = _items(validation.get("knowledge_issues"))
        blockers = _items(validation.get("blocking_reasons"))

        lines.extend([
            f"## {case_id}",
            "",
            f"- Source artifact: `{source_file}`",
            f"- Analysis run status: `{_text(case.get('run_status'))}`; DFD readiness: **{_text(validation.get('readiness'))}**; topology: **{_text(validation.get('topology'))}**",
            f"- Structural topology checks: **{topology}**",
            f"- DFD inventory: {counts.get('nodes', observed.get('dfd_nodes', 'n/a'))} nodes, {counts.get('flows', observed.get('dfd_flows', 'n/a'))} flows, {counts.get('zones', 'n/a')} zones, {counts.get('isolated_nodes', 'n/a')} isolated nodes",
            f"- Report sign-off ready: **{bool(case.get('signoff_ready', False))}**",
            "",
            "### Topology issues",
            "",
        ])
        lines.extend([f"- {issue}" for issue in topology_issues] or ["- None recorded."])
        lines.extend(["", "### Knowledge / classification issues", ""])
        lines.extend([f"- {issue}" for issue in knowledge_issues] or ["- None recorded."])
        lines.extend(["", "### Open owner questions", ""])
        if isinstance(questions, list) and questions:
            for question in questions:
                if not isinstance(question, dict):
                    continue
                qid = _text(question.get("id"), "question-id-missing")
                refs = question.get("affected_refs", [])
                refs_text = ", ".join(f"`{ref}`" for ref in refs) if isinstance(refs, list) and refs else "none recorded"
                lines.extend([
                    f"#### `{qid}` — {_text(question.get('status'))}",
                    "",
                    _quote(_text(question.get("question"), "Question text missing.")),
                    "",
                    f"Affected references: {refs_text}",
                    "",
                    "Owner: **pending**  ",
                    "Decision: **pending**  ",
                    "Evidence locator: **pending**  ",
                    "Rationale: **pending**",
                    "",
                ])
        else:
            lines.append("- No open questions recorded.")
            lines.append("")
        lines.extend(["### Full readiness blockers", ""])
        lines.extend([f"- {blocker}" for blocker in blockers] or ["- None recorded."])
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", required=True, help="CR8 qualification JSON")
    parser.add_argument("--output", required=True, help="Markdown output path")
    args = parser.parse_args()
    qualification_path = Path(args.qualification)
    output_path = Path(args.output)
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    report = build_report(qualification)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    print(json.dumps({
        "run_id": qualification.get("namespace"),
        "case_count": len(qualification.get("cases", [])),
        "output": str(output_path),
        "mode": qualification.get("mode"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
