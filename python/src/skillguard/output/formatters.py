"""
Three output formats:
 - human  (default for the bare CLI)
 - json   (schema-shaped dict, camelCase keys matching the npm package's
           `--format json` output byte-for-byte in structure)
 - sarif  (valid SARIF 2.1.0 for GitHub code-scanning upload -- the default
           the bundled GitHub Action invokes the CLI with)

Ported from src/output/formatters.ts. The TypeScript original validates its
JSON output against a `zod` schema (JsonOutputSchema); this port skips a
runtime schema-validation dependency and instead keeps the dict shape
literally identical to that schema by construction (see to_json_output()).
"""
from __future__ import annotations

import json
import re
from typing import List

from ..types import Finding, ScanResult, ScanWarning, Severity, SkillSetScanResult

_SARIF_TOOL_NAME = "SkillGuard"
_SARIF_TOOL_VERSION = "0.1.0"
_SARIF_INFO_URI = "https://github.com/RudrenduPaul/skillguard"


def _summarize(findings: List[Finding]) -> dict:
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


# SECURITY: strips ASCII control characters (the full C0 range 0x00-0x1F,
# including ESC 0x1B, CR, and LF, plus DEL 0x7F -- everything except tab)
# from strings that originate in the scan target before they reach
# format_human()'s terminal-facing output. A finding's file path and
# snippet are both attacker-controlled: a crafted filename or source line
# containing ANSI/terminal escape sequences, or embedded CR/LF bytes,
# printed verbatim can conceal or rewrite what a human sees when running
# `skillguard scan` locally. This does not affect the JSON/SARIF
# machine-readable formats or the exit code; it only protects a human
# directly reading the default human-readable CLI output. Ported from the
# same control in src/output/formatters.ts.
_CONTROL_CHAR_RE = re.compile("[\x00-\x08\x0a-\x1f\x7f]")


def sanitize_for_terminal(value: str) -> str:
    return _CONTROL_CHAR_RE.sub("�", value)


def to_json_output(result: ScanResult) -> dict:
    findings = []
    for f in result.findings:
        entry = {
            "ruleId": f.rule_id,
            "category": f.category,
            "severity": f.severity,
            "message": f.message,
            "file": f.file,
            "line": f.line,
        }
        if f.snippet is not None:
            entry["snippet"] = f.snippet
        findings.append(entry)

    return {
        "target": result.target,
        "filesScanned": result.files_scanned,
        "severityThreshold": result.severity_threshold,
        "exitCode": result.exit_code,
        "summary": _summarize(result.findings),
        "findings": findings,
        "timeouts": result.timeouts,
        "unscannedFiles": result.unscanned_files,
        "warnings": [{"code": w.code, "message": w.message} for w in result.warnings],
    }


def format_json(result: ScanResult) -> str:
    return json.dumps(to_json_output(result), indent=2)


def format_human(result: ScanResult) -> str:
    lines: List[str] = []
    lines.append(f"SkillGuard scan: {result.target}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append("")

    if len(result.findings) == 0:
        lines.append("No findings.")
    else:
        by_severity = _summarize(result.findings)
        lines.append(
            f"Findings: {len(result.findings)} "
            f"(HIGH: {by_severity['HIGH']}, MEDIUM: {by_severity['MEDIUM']}, LOW: {by_severity['LOW']})"
        )
        lines.append("")
        for finding in result.findings:
            file = sanitize_for_terminal(finding.file)
            lines.append(f"[{finding.severity}] {finding.category} {file}:{finding.line}")
            lines.append(f"  {finding.rule_id} — {finding.message}")
            if finding.snippet:
                lines.append(f"  > {sanitize_for_terminal(finding.snippet)}")
            lines.append("")

    if result.timeouts:
        lines.append("[TIMEOUT] files that exceeded the per-file scan timeout (scan continued):")
        for file in result.timeouts:
            lines.append(f"  - {sanitize_for_terminal(file)}")
        lines.append("")

    if result.unscanned_files:
        lines.append("Unscanned files (unsupported language, not silently skipped):")
        for file in result.unscanned_files:
            lines.append(f"  - {sanitize_for_terminal(file)}")
        lines.append("")

    if result.warnings:
        lines.append("Warnings:")
        for warning in result.warnings:
            sanitized = sanitize_for_terminal(warning.message)
            lines.append("\n".join(f"  {l}" for l in sanitized.split("\n")))
        lines.append("")

    result_word = "PASS" if result.exit_code == 0 else ("FAIL" if result.exit_code == 1 else "ERROR")
    lines.append(
        f"Result: {result_word} (exit code {result.exit_code}, severity threshold {result.severity_threshold})"
    )

    return "\n".join(lines)


def _sarif_level(severity: Severity) -> str:
    if severity == "HIGH":
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def format_sarif(result: ScanResult) -> str:
    rule_ids = list(dict.fromkeys(f.rule_id for f in result.findings))
    rules = []
    for rule_id in rule_ids:
        example = next(f for f in result.findings if f.rule_id == rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": example.message},
                "properties": {"category": example.category, "severity": example.severity},
            }
        )

    # BUGFIX (inherited from the TypeScript original): SARIF's results array
    # only ever carries findings, so a scan-level diagnostic (target not
    # found, a skipped invalid rule pack) has nowhere to go there.
    # result.warnings is surfaced via invocations[].toolExecutionNotifications
    # instead, the spec-correct place for tool diagnostics that are not
    # analysis results -- otherwise a CI engineer running the GitHub Action
    # (which defaults to --format sarif) would get a validly-shaped but
    # silently incomplete SARIF file on every scan-level warning.
    invocation = {
        "executionSuccessful": result.exit_code != 2,
        "toolExecutionNotifications": [
            {"descriptor": {"id": w.code}, "message": {"text": w.message}, "level": "warning"}
            for w in result.warnings
        ],
    }

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _SARIF_TOOL_NAME,
                        "informationUri": _SARIF_INFO_URI,
                        "version": _SARIF_TOOL_VERSION,
                        "rules": rules,
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": _sarif_level(f.severity),
                        "message": {"text": f.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file},
                                    "region": {"startLine": f.line},
                                }
                            }
                        ],
                    }
                    for f in result.findings
                ],
                "invocations": [invocation],
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def format_result(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return format_json(result)
    if fmt == "sarif":
        return format_sarif(result)
    return format_human(result)


# scan_skill_set() rendering. Rather than a parallel human/json/sarif
# formatter, a SkillSetScanResult is first flattened into a single ordinary
# ScanResult -- each per-skill finding/timeout/unscanned-file path prefixed
# with "<skillName>/" so it stays correctly relative to the skill-set's own
# target directory, and each per-skill ScanWarning's message prefixed the
# same way -- then handed to the exact same format_human/format_json/
# format_sarif above. This is the only place scan_skill_set()'s output
# touches this module: the three format functions themselves are
# untouched, so the single-skill `scan` command's output is completely
# unaffected by any of this. Ported from src/output/formatters.ts.

_SKILL_SET_SUMMARY_WARNING_CODE = "skill-set-summary"


def flatten_skill_set_result(result: SkillSetScanResult) -> ScanResult:
    findings: List[Finding] = []
    for skill in result.skills:
        for f in skill.result.findings:
            findings.append(
                Finding(
                    rule_id=f.rule_id,
                    category=f.category,
                    severity=f.severity,
                    message=f.message,
                    file=f"{skill.name}/{f.file}",
                    line=f.line,
                    snippet=f.snippet,
                )
            )
    # Skill-set-level (SG09) findings already carry a "<skillName>/<file>"
    # path (see skillguard/scan/skill_set.py), so they need no further
    # prefixing.
    findings.extend(result.findings)

    timeouts = [f"{skill.name}/{file}" for skill in result.skills for file in skill.result.timeouts]
    unscanned_files = [
        f"{skill.name}/{file}" for skill in result.skills for file in skill.result.unscanned_files
    ]

    per_skill_warnings = [
        ScanWarning(code=w.code, message=f"[{skill.name}] {w.message}")
        for skill in result.skills
        for w in skill.result.warnings
    ]

    if result.skills:
        skill_names = ", ".join(s.name for s in result.skills)
        summary_message = f"Skill set scan covered {len(result.skills)} skill(s): {skill_names}."
    else:
        summary_message = "Skill set scan covered 0 skills."
    summary_warning = ScanWarning(code=_SKILL_SET_SUMMARY_WARNING_CODE, message=summary_message)

    return ScanResult(
        target=result.targets_dir,
        findings=findings,
        timeouts=timeouts,
        unscanned_files=unscanned_files,
        warnings=[summary_warning, *result.warnings, *per_skill_warnings],
        files_scanned=sum(skill.result.files_scanned for skill in result.skills),
        severity_threshold=result.severity_threshold,
        exit_code=result.exit_code,
    )


def to_skill_set_json_output(result: SkillSetScanResult) -> dict:
    output = to_json_output(flatten_skill_set_result(result))
    output["skills"] = [s.name for s in result.skills]
    return output


def format_set_json(result: SkillSetScanResult) -> str:
    return json.dumps(to_skill_set_json_output(result), indent=2)


def format_set_human(result: SkillSetScanResult) -> str:
    if result.skills:
        header = f"Skills discovered: {len(result.skills)} ({', '.join(s.name for s in result.skills)})\n\n"
    else:
        header = "Skills discovered: 0\n\n"
    return header + format_human(flatten_skill_set_result(result))


def format_set_result(result: SkillSetScanResult, fmt: str) -> str:
    if fmt == "json":
        return format_set_json(result)
    if fmt == "sarif":
        return format_sarif(flatten_skill_set_result(result))
    return format_set_human(result)
