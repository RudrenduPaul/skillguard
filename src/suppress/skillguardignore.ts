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
 * minimatch itself is deliberately lenient (it treats most malformed glob
 * text as a literal match rather than throwing), so it can't be relied on to
 * reject a typo like a missing closing bracket. This checks bracket/brace
 * balance directly -- the realistic class of "invalid glob syntax" a user
 * actually hits in a suppression file -- then still runs the pattern through
 * minimatch.makeRe() as a defensive second check (it throws on a non-string
 * or a pattern over minimatch's 64KB length cap).
 */
function isPatternSyntaxValid(pattern: string): boolean {
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
    minimatch.makeRe(pattern, { dot: true });
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
