import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple

VULN_REQUIRED_KEYS = {
    "vulnerability_type",
    "confidence_score",
    "evidence_code",
    "explanation",
    "fix",
}


def strip_markdown_fences(text):
    """Remove markdown code fences from LLM output."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def extract_json_structure(text, open_char, close_char):
    """Extract the outermost JSON structure delimited by open/close chars."""
    start = text.find(open_char)
    end = text.rfind(close_char)
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No {open_char}...{close_char} structure found")
    return text[start:end + 1]


def _extract_first_json_value(text, expected_type=None):
    """
    Extract the first decodable JSON value from mixed LLM output text.

    This is more robust than naive first/last bracket slicing when the model
    emits extra prose such as "[note] ..." before the actual JSON payload.
    """
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch not in "[{":
            continue
        try:
            obj, _ = decoder.raw_decode(text[i:])
        except json.JSONDecodeError:
            continue
        if expected_type is None or isinstance(obj, expected_type):
            return obj
    raise ValueError("No decodable JSON payload found")


def parse_vulnerability_json_array(response):
    """Parse a JSON array of vulnerability findings from LLM output."""
    text = strip_markdown_fences(response)

    if text in ("[]", ""):
        return []
    parsed = _extract_first_json_value(text, expected_type=(list, dict))

    if isinstance(parsed, dict):

        findings = parsed.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError(
                "Vulnerability scanner output is not a JSON array")
        parsed = findings

    if not isinstance(parsed, list):
        raise ValueError("Vulnerability scanner output is not a JSON array")

    return [item for item in parsed if isinstance(item, dict)]


def parse_verification_response(response):
    """
    Parse the verification pass output.

    Expected: {"verified": [...], "new_findings": [...]}
    """
    text = strip_markdown_fences(response)
    parsed = _extract_first_json_value(text, expected_type=dict)

    if not isinstance(parsed, dict):
        raise ValueError("Verification output is not a JSON object")

    verified = parsed.get("verified", [])
    new_findings = parsed.get("new_findings", [])

    if not isinstance(verified, list):
        verified = []
    if not isinstance(new_findings, list):
        new_findings = []

    verified = [
        f for f in verified
        if isinstance(f, dict) and f.get("verdict", "CONFIRMED") != "REJECTED"
    ]

    return verified, [f for f in new_findings if isinstance(f, dict)]


def normalize_findings(findings):
    """Validate and normalize findings to the required 5-key schema."""
    normalized = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if not VULN_REQUIRED_KEYS.issubset(item.keys()):
            missing = VULN_REQUIRED_KEYS - set(item.keys())
            print(
                f"[Node 6]   Skipping malformed finding (missing: {missing})")
            continue
        entry = {
            "vulnerability_type": str(item["vulnerability_type"]),
            "confidence_score": str(item["confidence_score"]),
            "evidence_code": str(item["evidence_code"]),
            "explanation": str(item["explanation"]),
            "fix": str(item["fix"]),
        }
        if "line_numbers" in item:
            entry["line_numbers"] = str(item["line_numbers"])
        normalized.append(entry)
    return normalized


def deduplicate_findings(findings):
    """
    Remove duplicate/near-duplicate findings and consolidate same-category groups.

    Two passes:
    1. Within each vulnerability_type, merge findings whose evidence_code
       overlaps (one is a substring of the other). Keep the higher confidence.
    2. If multiple findings of the same type remain after pass 1, consolidate
       them into a single finding per type. The consolidated finding keeps the
       highest confidence, combines all evidence blocks, and merges explanations.
    """
    if len(findings) <= 1:
        return findings

    confidence_rank = {"High": 3, "Medium": 2, "Low": 1}

    by_type = {}
    for f in findings:
        vtype = f["vulnerability_type"]
        by_type.setdefault(vtype, []).append(f)

    deduplicated = []
    for vtype, group in by_type.items():

        kept = []
        for candidate in group:
            c_evidence = candidate["evidence_code"].strip()
            is_dup = False
            for i, existing in enumerate(kept):
                e_evidence = existing["evidence_code"].strip()
                if c_evidence in e_evidence or e_evidence in c_evidence:
                    c_rank = confidence_rank.get(
                        candidate["confidence_score"], 0)
                    e_rank = confidence_rank.get(
                        existing["confidence_score"], 0)
                    if c_rank > e_rank:
                        kept[i] = candidate
                    is_dup = True
                    break
            if not is_dup:
                kept.append(candidate)

        if len(kept) > 1:
            consolidated = _consolidate_same_type(kept, vtype)
            deduplicated.append(consolidated)
            print(
                f"[Node 6]   Consolidated {len(kept)} '{vtype}' findings into 1")
        else:
            deduplicated.extend(kept)

    return deduplicated


def _consolidate_same_type(findings, vtype):
    """
    Merge multiple findings of the same vulnerability type into one.

    - Keeps the highest confidence score.
    - Combines all evidence_code blocks (separated by markers).
    - Merges explanations into a numbered list.
    - Picks the most comprehensive fix (longest).
    """
    confidence_rank = {"High": 3, "Medium": 2, "Low": 1}

    best_confidence = max(
        findings,
        key=lambda f: confidence_rank.get(f["confidence_score"], 0),
    )["confidence_score"]

    evidence_parts = []
    explanation_parts = []
    line_number_parts = []
    longest_fix = ""

    for i, f in enumerate(findings, 1):
        evidence_parts.append(f["evidence_code"].strip())
        explanation_parts.append(f"({i}) {f['explanation'].strip()}")
        if f.get("line_numbers"):
            line_number_parts.append(f["line_numbers"])
        if len(f["fix"]) > len(longest_fix):
            longest_fix = f["fix"]

    result = {
        "vulnerability_type": vtype,
        "confidence_score": best_confidence,
        "evidence_code": "\n\n/* --- next instance --- */\n\n".join(evidence_parts),
        "explanation": f"{len(findings)} instances found:\n" + "\n\n".join(explanation_parts),
        "fix": longest_fix,
    }
    if line_number_parts:
        result["line_numbers"] = ", ".join(line_number_parts)
    return result


def _normalize_whitespace(text):
    """Collapse all whitespace runs to a single space for fuzzy matching."""
    return re.sub(r"\s+", " ", text.strip())


def validate_evidence(findings, source_code):
    """
    Reject findings whose evidence_code is fabricated.

    A finding passes validation if at least one meaningful line of its
    evidence_code (after whitespace normalization) appears verbatim in
    the source code. This catches the common LLM failure mode of
    paraphrasing code (wrong variable names, wrong types) instead of
    copying it.
    """
    normalized_source = _normalize_whitespace(source_code)
    validated = []

    for finding in findings:
        evidence = finding["evidence_code"].strip()
        if not evidence:
            continue

        lines = [l.strip() for l in evidence.split("\n") if l.strip()]

        meaningful = [
            l for l in lines
            if len(l) > 15
            and not re.match(r"^[{}\s/\*]*$", l)
            and not l.startswith("//")
            and not l.startswith("/*")
            and not l.startswith("...")
            and "/* --- next instance --- */" not in l
        ]

        if not meaningful:

            if _normalize_whitespace(evidence) in normalized_source:
                validated.append(finding)
            else:
                print(f"[Node 6]   REJECTED (fabricated evidence): "
                      f"{finding['vulnerability_type']} — "
                      f"evidence not found in source code")
            continue

        matched = any(
            _normalize_whitespace(line) in normalized_source
            for line in meaningful
        )

        if matched:
            validated.append(finding)
        else:
            print(f"[Node 6]   REJECTED (fabricated evidence): "
                  f"{finding['vulnerability_type']} — "
                  f"no evidence line matches source code")

    return validated


def write_security_report(security_report, final_c_code, input_path):
    """
    Write the full security report to /tmp/wise_security/<basename>/.

    Creates:
        /tmp/wise_security/<basename>/security_report.json
        /tmp/wise_security/<basename>/scanned_code.c

    Returns the report directory path.
    """

    basename = os.path.splitext(os.path.basename(input_path))[0] or "unknown"
    report_dir = os.path.join("/tmp", "wise_security", basename)
    os.makedirs(report_dir, exist_ok=True)

    json_path = os.path.join(report_dir, "security_report.json")
    with open(json_path, "w") as f:
        json.dump({
            "scan_timestamp": datetime.now().isoformat(),
            "input_file": input_path,
            "total_findings": len(security_report),
            "findings": security_report,
        }, f, indent=2)

    code_path = os.path.join(report_dir, "scanned_code.c")
    with open(code_path, "w") as f:
        f.write(final_c_code)

    return report_dir
