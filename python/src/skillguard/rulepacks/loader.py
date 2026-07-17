"""
Loads every rule pack under `rulepacks_dir`. A pack is a subdirectory
containing a pack.json manifest. Malformed JSON, a manifest that fails
schema validation, a minCoreVersion the running core doesn't satisfy, or an
unparseable/invalid rules file all cause that one pack to be skipped with a
warning -- the remaining valid packs still run (locked behavior). Nothing
here ever raises for a bad pack.

Ported from src/rulepacks/loader.ts.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List

import yaml

from ..errors import format_what_why_fix
from ..types import ScanWarning
from .manifest_schema import (
    PackManifest,
    PatternRule,
    ValidationError,
    parse_pack_manifest,
    parse_rules_file,
    semver_gte,
)

CORE_VERSION = "0.1.0"


@dataclass
class LoadedPack:
    manifest: PackManifest
    dir: str
    rules: List[PatternRule] = field(default_factory=list)
    """Empty for "structural" packs -- SG07's behavior is core-provided."""


@dataclass
class LoadPacksResult:
    packs: List[LoadedPack]
    warnings: List[ScanWarning]


def _skip_warning(pack_name: str, why: str, fix: str) -> ScanWarning:
    return ScanWarning(
        code="invalid-pack",
        message=format_what_why_fix(
            f'Skipped rule pack "{pack_name}" — it will not run for this scan.', why, fix
        ),
    )


def load_rule_packs(rulepacks_dir: str, core_version: str = CORE_VERSION) -> LoadPacksResult:
    warnings: List[ScanWarning] = []
    packs: List[LoadedPack] = []

    try:
        entry_names = sorted(os.listdir(rulepacks_dir))
    except OSError as err:
        warnings.append(
            ScanWarning(
                code="rulepacks-dir-unreadable",
                message=format_what_why_fix(
                    f'Could not read the rule packs directory "{rulepacks_dir}".',
                    str(err),
                    "Reinstall skillguard-cli, or pass a rulepacks_dir pointing at a valid packs directory.",
                ),
            )
        )
        return LoadPacksResult(packs, warnings)

    for name in entry_names:
        pack_dir = os.path.join(rulepacks_dir, name)
        if not os.path.isdir(pack_dir):
            continue
        manifest_path = os.path.join(pack_dir, "pack.json")
        if not os.path.exists(manifest_path):
            continue

        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                raw_manifest = json.load(fh)
        except (OSError, json.JSONDecodeError) as err:
            warnings.append(
                _skip_warning(
                    name,
                    f"pack.json is not valid JSON ({err}).",
                    f"Fix the JSON syntax in {manifest_path}.",
                )
            )
            continue

        try:
            manifest = parse_pack_manifest(raw_manifest if isinstance(raw_manifest, dict) else {})
        except ValidationError as err:
            detail = "; ".join(err.issues)
            warnings.append(
                _skip_warning(
                    name,
                    f"pack.json failed manifest validation: {detail}",
                    f"Fix the listed field(s) in {manifest_path} to match the rule-pack manifest contract.",
                )
            )
            continue

        if not semver_gte(core_version, manifest.min_core_version):
            warnings.append(
                _skip_warning(
                    manifest.name,
                    f"This pack requires skillguard-cli >= {manifest.min_core_version}, but the running core is {core_version}.",
                    "Upgrade skillguard-cli, or use an older version of this rule pack.",
                )
            )
            continue

        if manifest.kind == "structural":
            packs.append(LoadedPack(manifest=manifest, dir=pack_dir, rules=[]))
            continue

        rules_path = os.path.join(pack_dir, manifest.rules_file or "")
        try:
            with open(rules_path, "r", encoding="utf-8") as fh:
                raw_rules = fh.read()
        except OSError as err:
            warnings.append(
                _skip_warning(
                    manifest.name,
                    f'Could not read its rules file "{rules_path}" ({err}).',
                    f"Ensure rulesFile in {manifest_path} points at a file that exists alongside it.",
                )
            )
            continue

        try:
            parsed_yaml = yaml.safe_load(raw_rules)
        except yaml.YAMLError as err:
            warnings.append(
                _skip_warning(
                    manifest.name,
                    f'Its rules file "{rules_path}" is not valid YAML ({err}).',
                    "Fix the YAML syntax in the rules file.",
                )
            )
            continue

        try:
            rules = parse_rules_file(parsed_yaml if isinstance(parsed_yaml, dict) else {})
        except ValidationError as err:
            detail = "; ".join(err.issues)
            warnings.append(
                _skip_warning(
                    manifest.name,
                    f'Its rules file "{rules_path}" failed validation: {detail}',
                    "Fix the listed field(s) in the rules file to match the pattern-rule schema.",
                )
            )
            continue

        packs.append(LoadedPack(manifest=manifest, dir=pack_dir, rules=rules))

    return LoadPacksResult(packs, warnings)
