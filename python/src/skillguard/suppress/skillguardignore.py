"""
.skillguardignore: a glob-based path suppression file, same mental model as
.gitignore. Also supports inline `# skillguard-ignore: SGxx` comments,
handled separately by is_inline_suppressed() below since that operates on
file content rather than the ignore file.

Ported from src/suppress/skillguardignore.ts. The TypeScript original uses
the `minimatch` npm package with `{ dot: true, nobrace: true, noext: true }`
(brace-expansion and extglob syntax disabled -- see the ReDoS note below).
This Python port implements a small first-party glob-to-regex compiler
(glob_to_regex_pattern() below) with the same semantics rather than pulling
in a third-party glob-matching dependency: `*`/`?` match dotfiles (dot:true),
and `{`/`}`/`@(`/`+(` etc. are treated as literal characters (brace
expansion and extglob are never interpreted), matching MINIMATCH_OPTIONS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from ..errors import format_what_why_fix
from ..types import ScanWarning

# Hard cap on a single suppression line's length, enforced *before* the
# pattern is ever compiled to a regex. Belt-and-suspenders defense in depth,
# same rationale as the TypeScript original: .skillguardignore lines are
# hand-authored glob paths -- nothing legitimate needs anywhere close to
# this length.
MAX_PATTERN_LENGTH = 512


def _translate_glob(pattern: str) -> str:
    """
    Translates a minimatch-like glob pattern to a Python regex pattern
    string. Supports `*` (any run of non-separator characters), `**` (any
    run of characters, including `/`), `?` (a single non-separator
    character), and POSIX-style `[...]`/`[!...]` character classes.
    Brace expansion (`{a,b}`) and extglob (`@(...)`, `+(...)`, ...) syntax
    are NOT interpreted -- every other character, including `{`, `}`, `(`,
    `)`, `@`, `+`, `!`, is treated as a literal, matching the TypeScript
    original's `nobrace: true, noext: true` minimatch options. `dot: true`
    is implicit: `*`/`**`/`?` match a leading dot the same as any other
    character (no special-casing of dotfiles).
    """
    i, n = 0, len(pattern)
    out: List[str] = []
    while i < n:
        ch = pattern[i]
        if ch == "*":
            j = i
            while j < n and pattern[j] == "*":
                j += 1
            if j - i >= 2:
                out.append(".*")
            else:
                out.append("[^/]*")
            i = j
            continue
        if ch == "?":
            out.append("[^/]")
            i += 1
            continue
        if ch == "[":
            j = i + 1
            neg = j < n and pattern[j] in ("!", "^")
            if neg:
                j += 1
            start = j
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape("["))
                i += 1
                continue
            body = pattern[start:j]
            out.append("[" + ("^" if neg else "") + body + "]")
            i = j + 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(re.escape(ch))
        i += 1
    return "^" + "".join(out) + "$"


def compile_glob(pattern: str) -> "re.Pattern[str]":
    return re.compile(_translate_glob(pattern))


@dataclass
class IgnoreFileResult:
    patterns: List[str] = field(default_factory=list)
    warnings: List[ScanWarning] = field(default_factory=list)


def _is_pattern_syntax_valid(pattern: str) -> bool:
    """
    minimatch itself is deliberately lenient (it treats most malformed glob
    text as a literal match rather than throwing), so it can't be relied on
    to reject a typo like a missing closing bracket. This checks
    bracket/brace balance directly -- the realistic class of "invalid glob
    syntax" a user actually hits in a suppression file -- then still runs
    the pattern through the glob compiler as a defensive second check.
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        return False

    bracket_depth = 0
    brace_depth = 0
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1
        elif ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
        if bracket_depth < 0 or brace_depth < 0:
            return False
        i += 1
    if bracket_depth != 0 or brace_depth != 0:
        return False

    try:
        compile_glob(pattern)
        return True
    except re.error:
        return False


def load_ignore_file(ignore_file_path: str) -> IgnoreFileResult:
    """Reads and parses a .skillguardignore file. A missing file is not an error -- it just means no suppressions."""
    warnings: List[ScanWarning] = []
    path = Path(ignore_file_path)
    if not path.exists():
        return IgnoreFileResult([], warnings)

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        warnings.append(
            ScanWarning(
                code="ignore-file-unreadable",
                message=format_what_why_fix(
                    f'Could not read suppression file "{ignore_file_path}".',
                    f"The file exists but SkillGuard could not open it ({err}).",
                    "Check the file permissions, or remove --skillguardignore to scan without suppressions.",
                ),
            )
        )
        return IgnoreFileResult([], warnings)

    patterns: List[str] = []
    lines = re.split(r"\r?\n", raw)
    for idx, raw_line in enumerate(lines):
        line_no = idx + 1
        line = raw_line.strip()
        if line == "" or line.startswith("#"):
            continue

        if not _is_pattern_syntax_valid(line):
            warnings.append(
                ScanWarning(
                    code="invalid-glob",
                    message=format_what_why_fix(
                        f'Ignored invalid suppression pattern on line {line_no} of "{ignore_file_path}": "{line}".',
                        "The glob syntax could not be parsed, most likely from an unbalanced [ ] or { } bracket.",
                        "Fix or remove that line. The rest of the .skillguardignore file was still applied.",
                    ),
                )
            )
            continue

        patterns.append(line)

    return IgnoreFileResult(patterns, warnings)


_INLINE_SUPPRESS_RE = re.compile(r"#\s*skillguard-ignore:\s*(SG0[1-7])\b", re.IGNORECASE)


def is_inline_suppressed(file_content: str, line: int, category: str) -> bool:
    """
    Checks whether a finding at `line` (1-based) in `file_content` is
    suppressed by an inline `# skillguard-ignore: SGxx` comment on that same
    line or the line immediately above it (eslint-disable-next-line
    convention).
    """
    lines = re.split(r"\r?\n", file_content)
    candidates: List[str] = []
    same_idx = line - 1
    above_idx = line - 2
    if 0 <= same_idx < len(lines):
        candidates.append(lines[same_idx])
    if 0 <= above_idx < len(lines):
        candidates.append(lines[above_idx])

    for candidate in candidates:
        match = _INLINE_SUPPRESS_RE.search(candidate)
        if match and match.group(1).upper() == category.upper():
            return True
    return False
