import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ScannableFile } from '../walker';
import type { Finding } from '../types';
import { parseFrontmatter, type DeclaredScope } from './frontmatter-behavior-diff';

/**
 * SG09 — cross-skill privilege chaining (v1, sibling-path heuristic).
 *
 * SCOPE LIMITATION (read before extending this file): skillguard's walker
 * (src/walker.ts) discovers exactly one SKILL.md per scan target — it is
 * NOT a multi-skill-directory walker, and rewriting it to build a real
 * marketplace-wide dependency graph across every skill it can find is
 * explicitly out of scope for this module. What this module does instead,
 * within that existing single-skill-per-scan architecture: it scans the
 * skill currently being scanned ("skill A")'s own hooks/scripts for text
 * that *looks like* a reference to a sibling skill directory (a relative
 * path such as `../other-skill/...` or `../../other-skill/...`, including
 * the JS/Python equivalents `require(...)`, `import ... from ...`, and
 * `os.path.join('..', 'other-skill', ...)`), and — only when that
 * referenced skill's SKILL.md happens to be reachable on disk next to skill
 * A's own scan target (i.e. `path.resolve(absTarget, '..', name)`) — parses
 * skill B's frontmatter (reusing frontmatter-behavior-diff.ts's
 * parseFrontmatter, never duplicating that logic) and compares its declared
 * scope against skill A's own declared scope.
 *
 * This is a best-effort heuristic, not proof: it does not confirm skill A
 * actually invokes skill B (only that A's source text contains a
 * sibling-path-shaped string), it cannot see skills that live outside
 * skill A's immediate parent directory, and a referenced skill whose
 * SKILL.md cannot be located is reported as unverifiable rather than
 * silently assumed safe (matching src/walker.ts's own "never silently
 * dropped" principle for content it cannot classify).
 *
 * READ-ONLY CONTRACT: this module never reads anything from skill B beyond
 * its SKILL.md frontmatter text, and never walks or scans skill B's own
 * hooks/scripts — the same invariant frontmatter-behavior-diff.ts documents
 * for skill A itself.
 */

export interface SiblingSkillReference {
  /** The directory name referenced, e.g. "other-skill" in "../other-skill/hooks/setup.js". */
  siblingName: string;
  /** Skill A's file the reference was found in (relative to skill A's scan target). */
  file: string;
  line: number;
}

// Boundary characters that may legitimately precede a relative sibling path:
// start-of-string, whitespace, a quote, an opening paren/bracket, `=`, or `,`.
// A generic pattern rather than one regex per language, because the same
// `../<name>/` shape shows up verbatim inside JS `require()`/`import`
// string literals, Python string literals passed to `subprocess`, and bare
// shell command arguments alike.
const SIBLING_PATH_RE =
  /(?:^|[\s'"(=,[])(?:\.\.\/){1,2}([A-Za-z0-9_][A-Za-z0-9_.-]*)\//g;

// Python's os.path.join() splits '..' and the sibling name into separate
// string arguments rather than one path literal, so it needs its own
// pattern: os.path.join('..', 'other-skill', ...).
const OS_PATH_JOIN_RE =
  /os\.path\.join\(\s*['"]\.\.['"]\s*,\s*['"]([A-Za-z0-9_][A-Za-z0-9_.-]*)['"]/g;

function lineOfIndex(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function matchSiblingNames(content: string): { name: string; index: number }[] {
  const results: { name: string; index: number }[] = [];

  for (const re of [SIBLING_PATH_RE, OS_PATH_JOIN_RE]) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(content))) {
      results.push({ name: match[1], index: match.index });
    }
  }

  return results;
}

/**
 * Scans skill A's own scannable files for sibling-skill-path-shaped
 * references. Read-only: reads file bytes and pattern-matches, never
 * executes anything from the scan target (same invariant as
 * frontmatter-behavior-diff.ts's inferActualBehavior()).
 */
export function findSiblingSkillReferences(files: ScannableFile[]): SiblingSkillReference[] {
  const refs: SiblingSkillReference[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file.absPath, 'utf8');
    } catch {
      continue;
    }

    for (const { name, index } of matchSiblingNames(content)) {
      refs.push({ siblingName: name, file: file.relPath, line: lineOfIndex(content, index) });
    }
  }

  return refs;
}

/** Case-insensitively finds SKILL.md directly inside `dir`, mirroring src/walker.ts's own match. */
function findSkillMdInDir(dir: string): string | null {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return null;
  }

  for (const entry of entries) {
    if (entry.isFile() && entry.name.toUpperCase() === 'SKILL.MD') {
      return path.join(dir, entry.name);
    }
  }

  return null;
}

function describeScope(scope: DeclaredScope): string[] {
  const parts: string[] = [];
  if (scope.network) parts.push('network access');
  if (scope.filesystemWrite) parts.push('filesystem read-write access');
  return parts;
}

/**
 * Compares each detected sibling reference's target SKILL.md (when
 * reachable) against skill A's own declared scope, and produces findings
 * for privilege escalation or an unverifiable reference. See this file's
 * header comment for the v1 heuristic's scope limitation.
 */
export function diffCrossSkillChaining(
  ownDeclared: DeclaredScope,
  absTarget: string,
  references: SiblingSkillReference[]
): Finding[] {
  const findings: Finding[] = [];

  for (const ref of references) {
    const siblingDir = path.resolve(absTarget, '..', ref.siblingName);
    if (siblingDir === absTarget) continue; // self-reference, not a different skill

    const siblingSkillMdPath = findSkillMdInDir(siblingDir);
    if (!siblingSkillMdPath) {
      findings.push({
        ruleId: 'sg09-unverifiable-cross-skill-reference',
        category: 'SG09',
        severity: 'MEDIUM',
        message: `This skill references what looks like a sibling skill directory ("${ref.siblingName}"), but no SKILL.md could be found there to verify the combined permission scope of the two skills together.`,
        file: ref.file,
        line: ref.line,
      });
      continue;
    }

    let siblingContent: string;
    try {
      siblingContent = fs.readFileSync(siblingSkillMdPath, 'utf8');
    } catch {
      findings.push({
        ruleId: 'sg09-unverifiable-cross-skill-reference',
        category: 'SG09',
        severity: 'MEDIUM',
        message: `This skill references what looks like a sibling skill directory ("${ref.siblingName}"), and a SKILL.md exists there, but it could not be read to verify the combined permission scope of the two skills together.`,
        file: ref.file,
        line: ref.line,
      });
      continue;
    }

    const siblingDeclared = parseFrontmatter(siblingContent);
    if (!siblingDeclared) {
      findings.push({
        ruleId: 'sg09-unverifiable-cross-skill-reference',
        category: 'SG09',
        severity: 'MEDIUM',
        message: `This skill references what looks like a sibling skill directory ("${ref.siblingName}"), and a SKILL.md exists there, but its frontmatter could not be parsed to verify the combined permission scope of the two skills together.`,
        file: ref.file,
        line: ref.line,
      });
      continue;
    }

    const escalations: string[] = [];
    if (siblingDeclared.network && !ownDeclared.network) escalations.push('network access');
    if (siblingDeclared.filesystemWrite && !ownDeclared.filesystemWrite) {
      escalations.push('filesystem read-write access');
    }

    if (escalations.length > 0) {
      findings.push({
        ruleId: 'sg09-cross-skill-privilege-escalation',
        category: 'SG09',
        severity: 'HIGH',
        message: `This skill references sibling skill "${ref.siblingName}", whose SKILL.md declares ${escalations.join(' and ')} — a broader permission scope than this skill declares for itself (declared: ${describeScope(ownDeclared).join(', ') || 'none'}). Invoking that sibling skill could let this skill gain those permissions without declaring them.`,
        file: ref.file,
        line: ref.line,
      });
    }
  }

  return findings;
}
