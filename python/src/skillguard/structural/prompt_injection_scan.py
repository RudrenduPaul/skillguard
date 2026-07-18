"""
SG08 -- prompt-injection-via-skill-content. Scans SKILL.md's markdown body
(the instructional text a host agent reads and follows, distinct from the
YAML frontmatter SG07 already covers) for phrasing and encoding tricks
commonly used to override a host agent's system prompt or hijack its tool
routing (a read-only structural scan -- this module never executes
anything from the scan target, only reads file bytes and pattern-matches,
same invariant as structural/frontmatter_behavior_diff.py and
scan/semgrep_runner.py).

HONESTY NOTE (matches SG05's documented false-negative-rate discipline --
see rulepacks/data/sg05-obfuscated-payloads/rules.yml's header comment):
this is heuristic, regex-based pattern matching against known phrasing and
known hiding techniques. It is NOT semantic or LLM-based analysis. A
sufficiently novel or paraphrased injection attempt will not match these
fixed patterns and will produce a false negative. These checks catch
known, common instruction-override idioms and known text-hiding tricks --
they are best-effort coverage, not a complete answer to prompt injection.

Ported from src/ast/prompt-injection-scan.ts, including its exact rule IDs,
regex patterns (translated to Python `re` syntax), severities, and
messages, so the npm and PyPI packages flag the same SG08 findings for the
same SKILL.md content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

from ..types import Finding, Severity

_FRONTMATTER_RE = re.compile(r"^---\r?\n[\s\S]*?\r?\n---\r?\n?")


def split_frontmatter(content: str) -> Tuple[str, int]:
    """
    Strips SKILL.md's leading YAML frontmatter block (if present) and
    returns the remaining markdown body, plus how many lines the
    frontmatter block consumed so callers can translate a match offset
    inside `body` back into a 1-based line number in the original, full
    file.
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return content, 0
    consumed = match.group(0)
    offset_lines = consumed.count("\n")
    return content[len(consumed) :], offset_lines


def _line_at(text: str, index: int) -> int:
    """1-based line number of `index` within `text`. Mirrors frontmatter_behavior_diff.py's _first_match_line helper."""
    return text.count("\n", 0, index) + 1


@dataclass
class InjectionPatternRule:
    rule_id: str
    regex: "re.Pattern[str]"
    severity: Severity
    message: str


# Direct instruction-override phrasing. HIGH: this wording, if followed by
# the host agent, directly overrides its system prompt or hides behavior
# from the user -- a confirmed injection *attempt* even though whether the
# host agent actually complies is outside this static scanner's reach.
OVERRIDE_PATTERN_RULES: List[InjectionPatternRule] = [
    InjectionPatternRule(
        rule_id="sg08-ignore-prior-instructions",
        regex=re.compile(r"\bignore\s+(?:(?:all|previous|prior)\s+){1,2}instructions\b", re.IGNORECASE),
        severity="HIGH",
        message=(
            "SKILL.md body text instructs the reader to ignore its prior/system "
            "instructions -- a direct prompt-injection phrasing used to override a "
            "host agent's system prompt."
        ),
    ),
    InjectionPatternRule(
        rule_id="sg08-disregard-system-prompt",
        regex=re.compile(r"\bdisregard\s+(your|the)\s+system\s+prompt\b", re.IGNORECASE),
        severity="HIGH",
        message=(
            "SKILL.md body text instructs the reader to disregard its system prompt "
            "-- a direct prompt-injection phrasing used to override a host agent's "
            "system prompt."
        ),
    ),
    InjectionPatternRule(
        rule_id="sg08-fake-mode-switch",
        regex=re.compile(
            r"\byou\s+are\s+now\s+in\s+(developer|debug|unrestricted)\s+mode\b", re.IGNORECASE
        ),
        severity="HIGH",
        message=(
            "SKILL.md body text claims the host agent is now in developer/debug/"
            "unrestricted mode -- a common phrasing used to trick an agent into "
            "bypassing its normal safety behavior."
        ),
    ),
    InjectionPatternRule(
        rule_id="sg08-reveal-system-prompt",
        regex=re.compile(r"\breveal\s+your\s+(system\s+prompt|instructions)\b", re.IGNORECASE),
        severity="HIGH",
        message=(
            "SKILL.md body text instructs the reader to reveal its system prompt or "
            "instructions -- a common prompt-extraction phrasing."
        ),
    ),
    InjectionPatternRule(
        rule_id="sg08-hide-action-from-user",
        regex=re.compile(r"\bdo\s+not\s+(tell|inform|mention\s+to)\s+the\s+user\b", re.IGNORECASE),
        severity="HIGH",
        message=(
            "SKILL.md body text instructs the reader not to tell/inform/mention "
            "something to the user -- a common phrasing used to hide an agent's "
            "actions from the person it is working for."
        ),
    ),
]

# Invisible/zero-width Unicode characters commonly used to hide injected
# text from a human reviewer skimming the rendered markdown (the text is
# still there for an LLM tokenizer to read): zero-width space/joiner/
# non-joiner, word joiner, BOM, soft hyphen, bidi-override controls, and
# the Unicode "tag" block (U+E0000-U+E007F) -- a range with no legitimate
# use in skill documentation that has been used in real-world prompt-
# injection payloads to smuggle hidden instructions past visual review.
_INVISIBLE_CHARS_RE = re.compile(
    "[​‌‍⁠﻿­‪-‮⁦-⁩]|[\U000e0000-\U000e007f]"
)

# Suspiciously large base64-like encoded blocks embedded directly in
# SKILL.md's own instructional text (distinct from SG05, which scans
# *script* files for base64-into-eval/exec idioms -- this is about encoded
# payloads hidden inside the markdown the agent reads as instructions).
# Length 60+ of pure base64-alphabet characters is an arbitrary but
# deliberately conservative threshold -- short base64 strings (short
# tokens, sample IDs) are common and not by themselves suspicious.
_BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def _scan_override_patterns(body: str, offset_lines: int) -> List[Finding]:
    findings: List[Finding] = []
    for rule in OVERRIDE_PATTERN_RULES:
        for match in rule.regex.finditer(body):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="SG08",
                    severity=rule.severity,
                    message=rule.message,
                    file="",
                    line=_line_at(body, match.start()) + offset_lines,
                )
            )
    return findings


def _scan_invisible_chars(body: str, offset_lines: int) -> List[Finding]:
    findings: List[Finding] = []
    seen_lines = set()
    for match in _INVISIBLE_CHARS_RE.finditer(body):
        line = _line_at(body, match.start()) + offset_lines
        # Dedupe to one finding per line: a single hiding technique often
        # repeats an invisible character between every letter of a phrase,
        # and reporting each individually would flood the finding list
        # without adding signal beyond "this line contains hidden characters".
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(
            Finding(
                rule_id="sg08-hidden-unicode-characters",
                category="SG08",
                severity="MEDIUM",
                message=(
                    "SKILL.md body text contains invisible/zero-width Unicode "
                    "characters, which can be used to hide injected instructions "
                    "from a human reviewing the rendered markdown. Flagged for "
                    "manual review -- this is not by itself a confirmed exploit."
                ),
                file="",
                line=line,
            )
        )
    return findings


def _scan_base64_blocks(body: str, offset_lines: int) -> List[Finding]:
    findings: List[Finding] = []
    for match in _BASE64_BLOCK_RE.finditer(body):
        findings.append(
            Finding(
                rule_id="sg08-encoded-block-in-instructions",
                category="SG08",
                severity="MEDIUM",
                message=(
                    "SKILL.md body text contains a suspiciously large base64-like "
                    "encoded block embedded directly in the skill's instructional "
                    "text. Flagged for manual review -- this is not by itself a "
                    "confirmed exploit."
                ),
                file="",
                line=_line_at(body, match.start()) + offset_lines,
            )
        )
    return findings


def scan_prompt_injection(skill_md_content: str) -> List[Finding]:
    """
    Scans SKILL.md's markdown body (frontmatter stripped) for the three
    prompt-injection categories documented above. `file` is left empty on
    every returned Finding -- the caller (scan/index.py's scan_skill())
    fills it in with the SKILL.md path relative to the scan target, since
    this function has no notion of the scan target's root.
    """
    body, offset_lines = split_frontmatter(skill_md_content)
    return [
        *_scan_override_patterns(body, offset_lines),
        *_scan_invisible_chars(body, offset_lines),
        *_scan_base64_blocks(body, offset_lines),
    ]
