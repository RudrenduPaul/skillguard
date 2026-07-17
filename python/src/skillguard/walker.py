"""
File discovery: finds SKILL.md plus hooks/scripts under a target path, then
applies .skillguardignore glob suppression. v0.1 supported script languages
are JavaScript/TypeScript, Python, and shell (the languages the bundled
pattern rule packs have coverage for). Anything else found under a hooks/ or
scripts/ directory is reported as "unscanned" rather than silently dropped.

Ported from src/walker.ts, including the symlink-visibility bugfix: a
symlink is never followed, but its existence is always reported (either
suppressed by a matching ignore glob or added to unscanned_files) instead of
silently vanishing from every list, which would be a trivial scanner-evasion
vector for a tool whose job is scanning untrusted third-party content.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from .suppress.skillguardignore import compile_glob

ALWAYS_IGNORED_DIRS = {".git", "node_modules", ".skillguard-cache"}

SupportedLanguage = str  # "javascript" | "typescript" | "python" | "shell"

EXTENSION_LANGUAGE = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
}

# Directories whose contents are treated as hooks/scripts even without a recognized extension.
SCRIPT_ROLE_DIRS = {"hooks", "scripts"}


@dataclass
class ScannableFile:
    abs_path: str
    """Absolute path on disk."""
    rel_path: str
    """Path relative to the scan target, used in output."""
    language: SupportedLanguage


@dataclass
class WalkResult:
    skill_md_path: Optional[str]
    files: List[ScannableFile] = field(default_factory=list)
    unscanned_files: List[str] = field(default_factory=list)
    """Files under a hooks/scripts role directory with an unrecognized language, or unfollowed symlinks."""


def _is_under_script_role_dir(rel_path: str) -> bool:
    segments = rel_path.split("/")
    return any(segment in SCRIPT_ROLE_DIRS for segment in segments[:-1])


def _collect_all_files(dir_path: str, out: List[str], symlinks: List[str]) -> None:
    try:
        entries = list(os.scandir(dir_path))
    except OSError:
        return
    for entry in entries:
        # A symlink entry is reported (added to `symlinks`) but never
        # recursed into or read -- os.DirEntry.is_dir()/is_file() default to
        # follow_symlinks=True, so this check must come first or a symlinked
        # directory would be silently walked into.
        if entry.is_symlink():
            symlinks.append(entry.path)
            continue
        try:
            if entry.is_dir(follow_symlinks=False):
                if entry.name in ALWAYS_IGNORED_DIRS:
                    continue
                _collect_all_files(entry.path, out, symlinks)
            elif entry.is_file(follow_symlinks=False):
                out.append(entry.path)
        except OSError:
            continue


def walk(target_dir: str, ignore_globs: Optional[List[str]] = None) -> WalkResult:
    """
    Walks `target_dir`, applies `ignore_globs` (already-parsed
    .skillguardignore patterns) against paths relative to target_dir, and
    classifies each surviving file as SKILL.md, a scannable script, or
    unscanned.
    """
    ignore_globs = ignore_globs or []
    abs_target = os.path.abspath(target_dir)
    all_files: List[str] = []
    symlinks: List[str] = []
    _collect_all_files(abs_target, all_files, symlinks)

    compiled_globs = [compile_glob(g) for g in ignore_globs]

    def is_ignored(rel_path: str) -> bool:
        return any(g.match(rel_path) for g in compiled_globs)

    skill_md_path: Optional[str] = None
    files: List[ScannableFile] = []
    unscanned_files: List[str] = []

    for abs_path in all_files:
        rel_path = os.path.relpath(abs_path, abs_target).replace(os.sep, "/")

        if is_ignored(rel_path):
            continue

        base = os.path.basename(abs_path)
        if base.upper() == "SKILL.MD":
            skill_md_path = abs_path
            continue

        ext = os.path.splitext(abs_path)[1].lower()
        language = EXTENSION_LANGUAGE.get(ext)
        if language:
            files.append(ScannableFile(abs_path=abs_path, rel_path=rel_path, language=language))
        elif _is_under_script_role_dir(rel_path):
            unscanned_files.append(rel_path)

    # Symlinks are never followed (see _collect_all_files) but are always
    # reported as unscanned rather than silently vanishing, regardless of
    # which directory they're in -- a symlink is a security-relevant evasion
    # vector wherever it appears, not just inside hooks/scripts.
    for abs_path in symlinks:
        rel_path = os.path.relpath(abs_path, abs_target).replace(os.sep, "/")
        if is_ignored(rel_path):
            continue
        unscanned_files.append(rel_path)

    return WalkResult(skill_md_path=skill_md_path, files=files, unscanned_files=unscanned_files)
