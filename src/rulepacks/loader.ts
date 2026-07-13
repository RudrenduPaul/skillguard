import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  PackManifestSchema,
  RulesFileSchema,
  semverGte,
  type PackManifest,
  type PatternRule,
} from './manifest-schema';
import type { ScanWarning } from '../types';
import { formatWhatWhyFix } from '../errors';

export const CORE_VERSION = '0.1.0';

export interface LoadedPack {
  manifest: PackManifest;
  dir: string;
  /** Empty for "structural" packs — SG07's behavior is core-provided (src/ast). */
  rules: PatternRule[];
}

export interface LoadPacksResult {
  packs: LoadedPack[];
  warnings: ScanWarning[];
}

function skipWarning(packName: string, why: string, fix: string): ScanWarning {
  return {
    code: 'invalid-pack',
    message: formatWhatWhyFix(
      `Skipped rule pack "${packName}" — it will not run for this scan.`,
      why,
      fix
    ),
  };
}

/**
 * Loads every rule pack under `rulepacksDir`. A pack is a subdirectory
 * containing a pack.json manifest. Malformed JSON, a manifest that fails
 * schema validation, a minCoreVersion the running core doesn't satisfy, or
 * an unparseable/invalid rules file all cause that one pack to be skipped
 * with a warning — the remaining valid packs still run (locked behavior,
 * [redacted] Section 2.1). Nothing here ever throws for a bad pack.
 */
export function loadRulePacks(
  rulepacksDir: string,
  coreVersion: string = CORE_VERSION
): LoadPacksResult {
  const warnings: ScanWarning[] = [];
  const packs: LoadedPack[] = [];

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(rulepacksDir, { withFileTypes: true });
  } catch (err) {
    warnings.push({
      code: 'rulepacks-dir-unreadable',
      message: formatWhatWhyFix(
        `Could not read the rule packs directory "${rulepacksDir}".`,
        `${(err as Error).message}`,
        'Reinstall skillguard-cli, or pass --rulepacks-dir to point at a valid packs directory.'
      ),
    });
    return { packs, warnings };
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const packDir = path.join(rulepacksDir, entry.name);
    const manifestPath = path.join(packDir, 'pack.json');

    if (!fs.existsSync(manifestPath)) continue;

    let rawManifest: unknown;
    try {
      rawManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (err) {
      warnings.push(
        skipWarning(
          entry.name,
          `pack.json is not valid JSON (${(err as Error).message}).`,
          `Fix the JSON syntax in ${manifestPath}.`
        )
      );
      continue;
    }

    const parsed = PackManifestSchema.safeParse(rawManifest);
    if (!parsed.success) {
      const detail = parsed.error.issues
        .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
        .join('; ');
      warnings.push(
        skipWarning(
          entry.name,
          `pack.json failed manifest validation: ${detail}`,
          `Fix the listed field(s) in ${manifestPath} to match the rule-pack manifest contract.`
        )
      );
      continue;
    }

    const manifest = parsed.data;

    if (!semverGte(coreVersion, manifest.minCoreVersion)) {
      warnings.push(
        skipWarning(
          manifest.name,
          `This pack requires skillguard-cli >= ${manifest.minCoreVersion}, but the running core is ${coreVersion}.`,
          'Upgrade skillguard-cli, or use an older version of this rule pack.'
        )
      );
      continue;
    }

    if (manifest.kind === 'structural') {
      packs.push({ manifest, dir: packDir, rules: [] });
      continue;
    }

    const rulesPath = path.join(packDir, manifest.rulesFile as string);
    let rawRules: string;
    try {
      rawRules = fs.readFileSync(rulesPath, 'utf8');
    } catch (err) {
      warnings.push(
        skipWarning(
          manifest.name,
          `Could not read its rules file "${rulesPath}" (${(err as Error).message}).`,
          `Ensure rulesFile in ${manifestPath} points at a file that exists alongside it.`
        )
      );
      continue;
    }

    let parsedYaml: unknown;
    try {
      parsedYaml = parseYaml(rawRules);
    } catch (err) {
      warnings.push(
        skipWarning(
          manifest.name,
          `Its rules file "${rulesPath}" is not valid YAML (${(err as Error).message}).`,
          'Fix the YAML syntax in the rules file.'
        )
      );
      continue;
    }

    const rulesParsed = RulesFileSchema.safeParse(parsedYaml);
    if (!rulesParsed.success) {
      const detail = rulesParsed.error.issues
        .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
        .join('; ');
      warnings.push(
        skipWarning(
          manifest.name,
          `Its rules file "${rulesPath}" failed validation: ${detail}`,
          'Fix the listed field(s) in the rules file to match the pattern-rule schema.'
        )
      );
      continue;
    }

    packs.push({ manifest, dir: packDir, rules: rulesParsed.data.rules });
  }

  return { packs, warnings };
}
