import * as fs from 'node:fs';
import { minimatch } from 'minimatch';
import type { ScanWarning } from '../types';
import { formatWhatWhyFix } from '../errors';

/**
 * .skillguardignore: a glob-based path suppression file, same mental model as
 * .gitignore. Also supports inline `# skillguard-ignore: SGxx` comments,
 * handled separately by isInlineSuppressed() below since that operates on
 * file content rather than the ignore file.
 */

export interface IgnoreFileResult {
  patterns: string[];
  warnings: ScanWarning[];
}

/**
 * Hard cap on a single suppression line's length, enforced *before* the
 * pattern ever reaches minimatch. Belt-and-suspenders defense in depth so a
 * future minimatch option change can't silently reopen the ReDoS class this
 * module is written to avoid (see MINIMATCH_OPTIONS below). .skillguardignore
 * lines are hand-authored glob paths -- nothing legitimate needs anywhere
 * close to this length.
 */
const MAX_PATTERN_LENGTH = 512;

/**
 * SECURITY (verified via local reproduction, not theoretical): minimatch's
 * brace-expansion (`{a,b}`) and extglob (`@(...)`, `+(...)`, etc.) syntax
 * can compile to a regular expression with catastrophic backtracking on
 * ordinary input. Confirmed locally: the pattern `{a,a}` repeated 22 times
 * (a ~110-byte string) took 3.5+ seconds just to *compile* via
 * minimatch.makeRe() -- before it is even matched against a file path --
 * and the cost grows exponentially with each additional repetition, with
 * zero timeout protection anywhere in this module or its caller
 * (src/walker.ts). `.skillguardignore` is read from the *scan target
 * itself* by default (see src/scan/index.ts), i.e. from the exact
 * untrusted content SkillGuard exists to vet, so a hostile pattern here is
 * directly attacker-controlled input: a malicious skill submission can ship
 * a `.skillguardignore` line of this shape and hang any CI job that scans
 * it, indefinitely, with no per-file timeout able to intervene (that
 * mechanism only covers rule-pattern matching in semgrep-runner.ts, not
 * suppression-glob matching here). Neither brace expansion nor extglob is
 * meaningful for a `.gitignore`-style path-suppression file (gitignore
 * itself has no brace/extglob syntax), so both are disabled unconditionally
 * rather than attempting to detect "bad" patterns after the fact.
 */
export const MINIMATCH_OPTIONS = { dot: true, nobrace: true, noext: true } as const;

/**
 * minimatch itself is deliberately lenient (it treats most malformed glob
 * text as a literal match rather than throwing), so it can't be relied on to
 * reject a typo like a missing closing bracket. This checks bracket/brace
 * balance directly -- the realistic class of "invalid glob syntax" a user
 * actually hits in a suppression file -- then still runs the pattern through
 * minimatch.makeRe() as a defensive second check (it throws on a non-string
 * or a pattern over minimatch's 64KB length cap).
 */
function isPatternSyntaxValid(pattern: string): boolean {
  if (pattern.length > MAX_PATTERN_LENGTH) return false;

  let bracketDepth = 0;
  let braceDepth = 0;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\') {
      i++; // skip the escaped character
      continue;
    }
    if (ch === '[') bracketDepth++;
    else if (ch === ']') bracketDepth--;
    else if (ch === '{') braceDepth++;
    else if (ch === '}') braceDepth--;
    if (bracketDepth < 0 || braceDepth < 0) return false;
  }
  if (bracketDepth !== 0 || braceDepth !== 0) return false;

  try {
    minimatch.makeRe(pattern, MINIMATCH_OPTIONS);
    return true;
  } catch {
    return false;
  }
}

/** Reads and parses a .skillguardignore file. Missing file is not an error — it just means no suppressions. */
export function loadIgnoreFile(ignoreFilePath: string): IgnoreFileResult {
  const warnings: ScanWarning[] = [];
  if (!fs.existsSync(ignoreFilePath)) {
    return { patterns: [], warnings };
  }

  let raw: string;
  try {
    raw = fs.readFileSync(ignoreFilePath, 'utf8');
  } catch (err) {
    warnings.push({
      code: 'ignore-file-unreadable',
      message: formatWhatWhyFix(
        `Could not read suppression file "${ignoreFilePath}".`,
        `The file exists but SkillGuard could not open it (${(err as Error).message}).`,
        'Check the file permissions, or remove --skillguardignore to scan without suppressions.'
      ),
    });
    return { patterns: [], warnings };
  }

  const patterns: string[] = [];
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i].trim();
    if (line === '' || line.startsWith('#')) continue;

    if (!isPatternSyntaxValid(line)) {
      warnings.push({
        code: 'invalid-glob',
        message: formatWhatWhyFix(
          `Ignored invalid suppression pattern on line ${lineNo} of "${ignoreFilePath}": "${line}".`,
          'The glob syntax could not be parsed, most likely from an unbalanced [ ] or { } bracket.',
          'Fix or remove that line. The rest of the .skillguardignore file was still applied.'
        ),
      });
      continue;
    }

    patterns.push(line);
  }

  return { patterns, warnings };
}

const INLINE_SUPPRESS_RE = /#\s*skillguard-ignore:\s*(SG0[1-7])\b/i;

/**
 * Checks whether a finding at `line` (1-based) in `fileContent` is suppressed
 * by an inline `# skillguard-ignore: SGxx` comment on that same line or the
 * line immediately above it (eslint-disable-next-line convention).
 */
export function isInlineSuppressed(fileContent: string, line: number, category: string): boolean {
  const lines = fileContent.split(/\r?\n/);
  const candidates = [lines[line - 1], lines[line - 2]].filter(
    (l): l is string => typeof l === 'string'
  );
  return candidates.some((l) => {
    const match = INLINE_SUPPRESS_RE.exec(l);
    return !!match && match[1].toUpperCase() === category.toUpperCase();
  });
}
