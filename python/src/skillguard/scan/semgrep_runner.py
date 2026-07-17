"""
DEVIATION NOTE (inherited from the TypeScript original, src/scan/semgrep-
runner.ts): no official Semgrep distribution exists for either the npm or
PyPI ecosystem as a bundleable, zero-config dependency (Semgrep's own
distribution is a PyPI package plus platform binaries fetched from its own
release infrastructure at install time, which conflicts with the "bundled
rule packs, zero network fetch at scan time" architecture this project
locked in). Both the TypeScript and this Python port instead implement a
small, self-contained, in-process pattern engine that consumes the *same*
rule-pack contract (pack.json + a rules file) using a simplified, Semgrep-
inspired rule schema: a regex per rule, scoped to one or more of the three
v0.1-supported languages (javascript/typescript, python, shell).

Security invariant: this module never eval()s, exec()s, or dynamically
imports anything read from the scan target. It only ever reads file bytes
and runs a fixed, first-party compiled regex against them.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..rulepacks.manifest_schema import PatternRule
from ..types import Finding
from ..walker import ScannableFile


@dataclass
class LoadedRule:
    id: str
    message: str
    severity: str
    languages: List[str]
    regex: str
    flags: str
    category: str
    compiled: "re.Pattern[str]"
    is_global: bool


def _js_flags_to_python(flags: str) -> int:
    py_flags = 0
    if "i" in flags:
        py_flags |= re.IGNORECASE
    return py_flags


def compile_rules(packs) -> List[LoadedRule]:
    """
    Flattens loaded packs' pattern rules into ready-to-run rules,
    pre-compiling each regex once so per-file scanning doesn't recompile on
    every file. `packs` is any iterable of objects exposing
    `.manifest.category` and `.rules` (a list of PatternRule) -- matches
    rulepacks.loader.LoadedPack.
    """
    compiled: List[LoadedRule] = []
    for pack in packs:
        for rule in pack.rules:
            try:
                py_flags = _js_flags_to_python(rule.flags or "gi")
                pattern = re.compile(rule.regex, py_flags)
            except re.error:
                # Invalid regex in an otherwise-valid manifest -- skip just
                # this rule rather than the whole pack; loader.py already
                # validated shape, not that the regex source compiles.
                continue
            compiled.append(
                LoadedRule(
                    id=rule.id,
                    message=rule.message,
                    severity=rule.severity,
                    languages=rule.languages,
                    regex=rule.regex,
                    flags=rule.flags,
                    category=pack.manifest.category,
                    compiled=pattern,
                    is_global="g" in (rule.flags or "gi"),
                )
            )
    return compiled


def _build_line_starts(content: str) -> List[int]:
    """
    Precomputes the start offset of every line in `content` once per file,
    so looking up the line number for a match index is a binary search
    (O(log n)) instead of a linear rescan from the start of the file for
    every match.
    """
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_number_from_index(line_starts: List[int], index: int) -> int:
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= index:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


# How many matches of a single global rule to process between elapsed-time
# checks. The per-file timeout is cooperative (a single synchronous regex
# match pass can't be preempted mid-scan in this single-threaded engine), so
# this bounds the *number of matches* a single rule can process past the
# configured budget rather than the wall-clock time directly.
_MATCH_TIMEOUT_CHECK_INTERVAL = 25


def _default_clock() -> float:
    return time.monotonic() * 1000.0


@dataclass
class RunRulesResult:
    findings: List[Finding] = field(default_factory=list)
    timed_out_files: List[str] = field(default_factory=list)


def run_rules(
    files: List[ScannableFile],
    rules: List[LoadedRule],
    timeout_ms: int,
    clock: Optional[Callable[[], float]] = None,
) -> RunRulesResult:
    """
    Runs every applicable rule against every file, sequentially. Each file
    gets a cooperative per-file timeout budget: elapsed time is checked
    between rules and periodically between repeated matches of the same
    rule, so a file whose ruleset (or a single rule matching many times)
    takes longer than `timeout_ms` is marked [TIMEOUT] and scanning moves on
    to the next file rather than dropping it silently or hanging
    indefinitely.

    KNOWN LIMITATION (inherited from the TypeScript original, not fixed
    here): this is still a *cooperative* timeout, checked between matches. A
    single pathological regex (catastrophic backtracking / ReDoS) can still
    block this scan for an unbounded time inside one match attempt, with no
    opportunity for this loop to intervene. Fully bounding that case
    requires running rule evaluation in a subprocess/worker and terminating
    it on timeout -- a real architecture change, not a same-pass hotfix.
    """
    clock = clock or _default_clock
    findings: List[Finding] = []
    timed_out_files: List[str] = []

    for file in files:
        try:
            with open(file.abs_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue

        applicable_rules = [r for r in rules if file.language in r.languages]
        started_at = clock()
        timed_out = False
        line_starts = _build_line_starts(content)

        for rule in applicable_rules:
            if clock() - started_at > timeout_ms:
                timed_out = True
                break

            matches_since_check = 0
            for match in rule.compiled.finditer(content):
                line = _line_number_from_index(line_starts, match.start())
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        message=rule.message,
                        file=file.rel_path,
                        line=line,
                        snippet=match.group(0)[:200],
                    )
                )
                if not rule.is_global:
                    break

                matches_since_check += 1
                if matches_since_check >= _MATCH_TIMEOUT_CHECK_INTERVAL:
                    matches_since_check = 0
                    if clock() - started_at > timeout_ms:
                        timed_out = True
                        break

            if timed_out:
                break

        if timed_out:
            timed_out_files.append(file.rel_path)

    return RunRulesResult(findings=findings, timed_out_files=timed_out_files)
