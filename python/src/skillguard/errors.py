"""
Every error and warning surfaced by SkillGuard follows a fixed WHAT/WHY/FIX
three-line format, so a CI engineer trusting SkillGuard as a blocking gate
always knows what broke, why, and how to fix it. Ported verbatim from
src/errors.ts.
"""
from __future__ import annotations


def format_what_why_fix(what: str, why: str, fix: str) -> str:
    return f"WHAT: {what}\nWHY: {why}\nFIX: {fix}"


class SkillGuardError(Exception):
    def __init__(self, what: str, why: str, fix: str) -> None:
        super().__init__(format_what_why_fix(what, why, fix))
        self.what = what
        self.why = why
        self.fix = fix
