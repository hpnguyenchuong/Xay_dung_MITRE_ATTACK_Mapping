import csv
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

RE_FINDINGS = BASE_DIR / "datasets" / "re_findings.json"
GROUND_TRUTH = BASE_DIR / "datasets" / "ground_truth.json"
OUTPUT = BASE_DIR / "detection" / "q3_fusion_test_results.csv"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize_technique(value):
    if value is None:
        return "N/A"

    if isinstance(value, list):
        return ",".join(value)

    return str(value)


def score_finding(finding):
    confidence = int(finding.get("confidence", 50))

    evidence_score = 0
    if finding.get("evidence"):
        evidence_score += 20
    if finding.get("source"):
        evidence_score += 10
    if finding.get("artifact"):
        evidence_score += 10

    mitre_score = 0
    if finding.get("enterprise_technique") or finding.get("enterprise"):
        mitre_score += 15
    if finding.get("ics_technique") or finding.get("ics"):
        mitre_score += 15

    final_score = min(100, int(confidence * 0.5 + evidence_score + mitre_score))
    return final_score


def severity_from_score(score):
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def main():
    findings = load_json(RE_FINDINGS)
    ground_truth = load_json(GROUND_TRUTH)

    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("data", []))

    if isinstance(ground_truth, dict):
        ground_truth_items = ground_truth.get("ground_truth", ground_truth.get("data", []))
    else:
        ground_truth_items = ground_truth

    gt_map = {}

    for item in ground_truth_items:
        artifact = item.get("artifact") or item.get("artifact_id") or item.get("name")
        expected = (
            item.get("expected_technique")
            or item.get("technique")
            or item.get("enterprise_technique")
            or item.get("ics_technique")
        )
        if artifact:
            gt_map[str(artifact).lower()] = normalize_technique(expected)

    rows = []

    for finding in findings:
        artifact = (
            finding.get("artifact")
            or finding.get("artifact_id")
            or finding.get("name")
            or finding.get("indicator")
            or "unknown"
        )

        enterprise = (
            finding.get("enterprise_technique")
            or finding.get("enterprise")
            or finding.get("mitre_enterprise")
            or "N/A"
        )

        ics = (
            finding.get("ics_technique")
            or finding.get("ics")
            or finding.get("mitre_ics")
            or "N/A"
        )

        final_score = score_finding(finding)
        severity = severity_from_score(final_score)

        expected = gt_map.get(str(artifact).lower(), "N/A")

        predicted = normalize_technique(ics if ics != "N/A" else enterprise)
        matched = expected != "N/A" and expected in predicted

        rows.append({
            "artifact": artifact,
            "source": finding.get("source", "N/A"),
            "predicted_enterprise": normalize_technique(enterprise),
            "predicted_ics": normalize_technique(ics),
            "expected": expected,
            "matched_ground_truth": matched,
            "confidence": finding.get("confidence", "N/A"),
            "fusion_score": final_score,
            "severity": severity,
            "evidence": finding.get("evidence", "N/A")
        })

    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "artifact",
            "source",
            "predicted_enterprise",
            "predicted_ics",
            "expected",
            "matched_ground_truth",
            "confidence",
            "fusion_score",
            "severity",
            "evidence"
        ])
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    correct = sum(1 for row in rows if row["matched_ground_truth"] is True)
    accuracy = correct / total if total else 0

    print(f"[OK] Exported: {OUTPUT}")
    print(f"[INFO] Total findings: {total}")
    print(f"[INFO] Ground-truth matched: {correct}")
    print(f"[INFO] Accuracy: {accuracy:.2%}")


if __name__ == "__main__":
    main()
