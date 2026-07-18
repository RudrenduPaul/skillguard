import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseFrontmatter } from './frontmatter-behavior-diff';

/**
 * SG10 — marketplace typosquatting detection. Extracts the declared `name`
 * field from SKILL.md's YAML frontmatter (via frontmatter-behavior-diff.ts's
 * shared parseFrontmatter -- not a second YAML-frontmatter parser) and
 * compares it against rulepacks/sg10-marketplace-typosquatting/known-names.json,
 * a small bundled starter list of well-known package/tool names (not a live
 * or comprehensive marketplace registry — see that pack's pack.json). A
 * near-miss (edit distance 1-2, not an exact match) suggests the declared
 * name may be impersonating a popular tool.
 *
 * This module never executes anything from the scan target, only reads
 * SKILL.md content already handed to it and pattern-matches — same
 * read-only invariant as src/ast/frontmatter-behavior-diff.ts.
 */

export interface DeclaredName {
  name: string;
  /** 1-based line number within skillMdContent where the `name:` field appears. */
  line: number;
}

/**
 * Extracts the declared `name` field (and the line it appears on) from
 * SKILL.md's YAML frontmatter. Returns null when there is no frontmatter
 * block, the frontmatter isn't valid YAML, or no non-empty `name` field is
 * declared — in every case there is nothing to compare. A thin wrapper
 * around parseFrontmatter()'s `name`/`nameLine` fields (added there
 * specifically so this module didn't need its own duplicate frontmatter
 * parser), narrowing its `string | null` name to this module's
 * name-required DeclaredName shape.
 */
export function parseDeclaredName(skillMdContent: string): DeclaredName | null {
  const declared = parseFrontmatter(skillMdContent);
  if (!declared || declared.name === null) return null;

  return { name: declared.name, line: declared.nameLine ?? 1 };
}

/**
 * Pure Levenshtein edit-distance implementation (insertions, deletions,
 * substitutions each cost 1) — no dependency, single-row DP.
 */
export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prevRow = Array.from({ length: n + 1 }, (_, j) => j);
  let currRow = new Array<number>(n + 1).fill(0);

  for (let i = 1; i <= m; i++) {
    currRow[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      currRow[j] = Math.min(
        prevRow[j] + 1, // deletion
        currRow[j - 1] + 1, // insertion
        prevRow[j - 1] + cost // substitution
      );
    }
    [prevRow, currRow] = [currRow, prevRow];
  }

  return prevRow[n];
}

export interface TyposquatMatch {
  knownName: string;
  distance: number;
}

/** Names shorter than this are excluded from comparison — too easy to false-positive on. */
const MIN_NAME_LENGTH_FOR_CHECK = 4;

/**
 * Compares declaredName against every entry in knownNames. A known name is
 * flagged when it is not an exact match (case-insensitive) but its edit
 * distance from declaredName is 1 or 2, and both names clear a minimum
 * length (short names produce too many coincidental near-misses to be
 * meaningful).
 */
export function findTyposquatMatches(declaredName: string, knownNames: string[]): TyposquatMatch[] {
  const normalizedDeclared = declaredName.toLowerCase();
  if (normalizedDeclared.length < MIN_NAME_LENGTH_FOR_CHECK) return [];

  const matches: TyposquatMatch[] = [];
  for (const knownName of knownNames) {
    const normalizedKnown = knownName.toLowerCase();
    if (normalizedKnown.length < MIN_NAME_LENGTH_FOR_CHECK) continue;
    if (normalizedDeclared === normalizedKnown) continue; // exact match is presumably the real thing

    // A 1-2 edit distance can't span a larger length gap than that, but
    // checking it up front skips the DP for obviously unrelated pairs.
    if (Math.abs(normalizedDeclared.length - normalizedKnown.length) > 2) continue;

    const distance = levenshteinDistance(normalizedDeclared, normalizedKnown);
    if (distance >= 1 && distance <= 2) {
      matches.push({ knownName, distance });
    }
  }

  return matches;
}

const DEFAULT_KNOWN_NAMES_PATH = path.join(
  __dirname,
  '..',
  '..',
  'rulepacks',
  'sg10-marketplace-typosquatting',
  'known-names.json'
);

/**
 * Loads the bundled known-names seed list. Fail-soft: a missing or corrupt
 * file yields an empty list (no findings, no crash) rather than throwing —
 * same philosophy as loadRulePacks()/loadStructuralAnalyzers().
 */
export function loadKnownNames(knownNamesPath: string = DEFAULT_KNOWN_NAMES_PATH): string[] {
  try {
    const raw = fs.readFileSync(knownNamesPath, 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is string => typeof entry === 'string');
  } catch {
    return [];
  }
}
