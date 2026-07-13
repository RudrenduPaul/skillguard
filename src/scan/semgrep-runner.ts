import * as fs from 'node:fs';
import type { ScannableFile } from '../walker';
import type { PatternRule } from '../rulepacks/manifest-schema';
import type { Finding, RuleCategory } from '../types';

/**
 * DEVIATION NOTE (documented per the build instructions — no real "official
 * npm Semgrep wrapper" exists to bundle): the locked [redacted] calls for
 * invoking Semgrep via "the official @semgrep/semgrep npm wrapper." No such
 * package exists on the npm registry — Semgrep's only official distribution
 * is the `semgrep` PyPI package plus platform binaries, with no npm-native
 * install path. Depending on it would break the locked "zero required
 * config" / `npx skillguard-cli scan` success criterion for anyone without a
 * separate Python toolchain, and would also violate the bundled-in-npm-
 * package / no-remote-fetch constraint (Architecture finding 1) since the
 * platform binary itself is fetched from Semgrep's own release infra at
 * install time, not bundled.
 *
 * This module instead implements a small, self-contained, in-process pattern
 * engine that consumes the *same* rule-pack contract (pack.json + a rules
 * file) using a simplified, Semgrep-inspired rule schema: a regex per rule,
 * scoped to one or more of the three v0.1-supported languages
 * (javascript/typescript, python, shell). This keeps the "bundled, no
 * network fetch, no eval/require of scan-target content" architecture intact
 * while remaining fully swappable for a real Semgrep binary invocation later
 * without changing the rule-pack contract or any caller of this module.
 *
 * Security invariant ([redacted] Section 1, finding 2): this module never
 * eval()s, require()s, or dynamically imports anything read from the scan
 * target. It only ever reads file bytes and runs a fixed, first-party
 * RegExp against them.
 */

export interface RunRulesOptions {
  timeoutMs: number;
  /** Injectable clock so tests can simulate a slow file deterministically. */
  clock?: () => number;
}

export interface RunRulesResult {
  findings: Finding[];
  /** Relative paths of files that hit the per-file timeout. */
  timedOutFiles: string[];
}

interface LoadedRule extends PatternRule {
  category: RuleCategory;
  compiled: RegExp;
}

/**
 * Flattens loaded packs' pattern rules into ready-to-run rules, pre-compiling
 * each regex once so per-file scanning doesn't recompile on every file.
 */
export function compileRules(
  packs: { manifest: { category: RuleCategory }; rules: PatternRule[] }[]
): LoadedRule[] {
  const compiled: LoadedRule[] = [];
  for (const pack of packs) {
    for (const rule of pack.rules) {
      let re: RegExp;
      try {
        re = new RegExp(rule.regex, rule.flags ?? 'gi');
      } catch {
        // Invalid regex in an otherwise-valid manifest — skip just this rule
        // rather than the whole pack; loader.ts already validated shape, not
        // that the regex source compiles.
        continue;
      }
      compiled.push({ ...rule, category: pack.manifest.category, compiled: re });
    }
  }
  return compiled;
}

function lineNumberAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) line++;
  }
  return line;
}

/**
 * Runs every applicable rule against every file, sequentially (v0.1
 * performance decision — no worker pool). Each file gets a cooperative
 * per-file timeout budget: elapsed time is checked between rules, so a file
 * whose ruleset takes longer than `timeoutMs` is marked [TIMEOUT] and
 * scanning moves on to the next file rather than dropping it silently.
 */
export function runRules(
  files: ScannableFile[],
  rules: LoadedRule[],
  options: RunRulesOptions
): RunRulesResult {
  const clock = options.clock ?? Date.now;
  const findings: Finding[] = [];
  const timedOutFiles: string[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file.absPath, 'utf8');
    } catch {
      continue;
    }

    const applicableRules = rules.filter((rule) => rule.languages.includes(file.language));
    const startedAt = clock();
    let timedOut = false;

    for (const rule of applicableRules) {
      if (clock() - startedAt > options.timeoutMs) {
        timedOut = true;
        break;
      }

      rule.compiled.lastIndex = 0;
      let match: RegExpExecArray | null;
      // Guard against a rule authored without the global flag looping forever.
      const isGlobal = rule.compiled.global;
      // eslint-disable-next-line no-cond-assign
      while ((match = rule.compiled.exec(content))) {
        const line = lineNumberAt(content, match.index);
        findings.push({
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          message: rule.message,
          file: file.relPath,
          line,
          snippet: match[0].slice(0, 200),
        });
        if (!isGlobal) break;
      }
    }

    if (timedOut) {
      timedOutFiles.push(file.relPath);
    }
  }

  return { findings, timedOutFiles };
}
