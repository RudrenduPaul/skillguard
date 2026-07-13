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

/**
 * Precomputes the start offset of every line in `content` once per file, so
 * looking up the line number for a match index is a binary search (O(log n))
 * instead of a linear rescan from the start of the file.
 *
 * BUGFIX: the previous implementation (`lineNumberAt`) rescanned from index 0
 * on every single match, which is O(fileSize) per match and therefore
 * O(fileSize x matchCount) for a file with many matches — effectively
 * quadratic. A file with tens of thousands of matches (trivially producible,
 * accidentally or adversarially — e.g. a large generated file that happens
 * to repeat a credential-shaped token) measurably took several seconds of
 * real wall-clock time against a 200ms configured --timeout in manual
 * testing, dramatically undermining the "hard per-file timeout" security
 * invariant.
 */
function buildLineStarts(content: string): number[] {
  const lineStarts = [0];
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) lineStarts.push(i + 1);
  }
  return lineStarts;
}

function lineNumberFromIndex(lineStarts: number[], index: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    if (lineStarts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * How many matches of a single global rule to process between elapsed-time
 * checks. The [redacted]-locked per-file timeout is cooperative (a single
 * synchronous RegExp#exec call can't be preempted from within the same JS
 * thread), so this bounds the *number of matches* a single rule can process
 * past the configured budget rather than the wall-clock time directly. A
 * small interval keeps the worst-case overrun small without adding
 * significant per-match overhead from clock() calls.
 */
const MATCH_TIMEOUT_CHECK_INTERVAL = 25;

/**
 * Runs every applicable rule against every file, sequentially (v0.1
 * performance decision — no worker pool). Each file gets a cooperative
 * per-file timeout budget: elapsed time is checked between rules and
 * periodically between repeated matches of the same rule, so a file whose
 * ruleset (or a single rule matching many times) takes longer than
 * `timeoutMs` is marked [TIMEOUT] and scanning moves on to the next file
 * rather than dropping it silently or hanging indefinitely.
 *
 * KNOWN LIMITATION (not fixed here — escalated as needing a design decision,
 * see the code-review report this shipped with): this is still a
 * *cooperative* timeout, checked between matches. A single pathological
 * regex (catastrophic backtracking / ReDoS) can still block the event loop
 * for an unbounded time inside one synchronous `exec()` call, with no
 * opportunity for this loop to intervene. Fully bounding that case requires
 * running rule evaluation in a worker thread and calling
 * `worker.terminate()` on timeout — a real architecture change, not a
 * same-pass hotfix.
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
    const lineStarts = buildLineStarts(content);

    for (const rule of applicableRules) {
      if (clock() - startedAt > options.timeoutMs) {
        timedOut = true;
        break;
      }

      rule.compiled.lastIndex = 0;
      let match: RegExpExecArray | null;
      // Guard against a rule authored without the global flag looping forever.
      const isGlobal = rule.compiled.global;
      let matchesSinceCheck = 0;
      // eslint-disable-next-line no-cond-assign
      while ((match = rule.compiled.exec(content))) {
        const line = lineNumberFromIndex(lineStarts, match.index);
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

        matchesSinceCheck++;
        if (matchesSinceCheck >= MATCH_TIMEOUT_CHECK_INTERVAL) {
          matchesSinceCheck = 0;
          if (clock() - startedAt > options.timeoutMs) {
            timedOut = true;
            break;
          }
        }
      }

      if (timedOut) break;
    }

    if (timedOut) {
      timedOutFiles.push(file.relPath);
    }
  }

  return { findings, timedOutFiles };
}
