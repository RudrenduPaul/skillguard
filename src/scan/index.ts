import * as fs from 'node:fs';
import * as path from 'node:path';
import { walk } from '../walker';
import { loadRulePacks, CORE_VERSION } from '../rulepacks/loader';
import { compileRules, runRules } from './semgrep-runner';
import { loadIgnoreFile, isInlineSuppressed } from '../suppress/skillguardignore';
import {
  parseFrontmatter,
  inferActualBehavior,
  diffFrontmatterBehavior,
} from '../ast/frontmatter-behavior-diff';
import { meetsThreshold, type ScanOptions, type ScanResult, type Severity } from '../types';
import { formatWhatWhyFix } from '../errors';

/*
 * Data flow (locked at [redacted], reproduced here for anyone reading this
 * file first):
 *
 *   target path
 *        |
 *        v
 *   .skillguardignore loaded  -> ignore globs (+ warnings for invalid lines)
 *        |
 *        v
 *   walker.ts                 -> SKILL.md path, scannable files, unscanned files
 *        |
 *        v
 *   rulepacks/loader.ts       -> loaded packs (invalid packs skipped + warned)
 *        |
 *    +---+-----------------------------+
 *    v                                 v
 *  semgrep-runner.ts (SG01-06,       ast/frontmatter-behavior-diff.ts (SG07:
 *  partial SG05), per-file           declared vs actual scope, read-only)
 *  timeout enforced
 *    |                                 |
 *    +-----------------+---------------+
 *                       v
 *              inline suppression filter (# skillguard-ignore: SGxx)
 *                       v
 *              severity threshold -> exit code (0 clean / 1 fail / 2 error)
 */

const DEFAULT_SEVERITY_THRESHOLD: Severity = 'HIGH';
const DEFAULT_TIMEOUT_MS = 10_000;

function bundledRulepacksDir(): string {
  // dist/scan/index.js -> ../../rulepacks (package root's rulepacks/ dir),
  // shipped via package.json "files" so it's present in the published tarball.
  return path.join(__dirname, '..', '..', 'rulepacks');
}

export async function scanSkill(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const severityThreshold = options.severityThreshold ?? DEFAULT_SEVERITY_THRESHOLD;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const rulepacksDir = options.rulepacksDir ?? bundledRulepacksDir();

  const absTarget = path.resolve(target);

  if (!fs.existsSync(absTarget)) {
    return {
      target: absTarget,
      findings: [],
      timeouts: [],
      unscannedFiles: [],
      filesScanned: 0,
      severityThreshold,
      warnings: [
        {
          code: 'target-not-found',
          message: formatWhatWhyFix(
            `Target path "${absTarget}" does not exist.`,
            'SkillGuard scans a directory containing a skill (SKILL.md plus hooks/scripts) and needs a real path to start from.',
            'Pass a valid directory path, e.g. npx skillguard-cli scan ./my-skill'
          ),
        },
      ],
      exitCode: 2,
    };
  }

  const ignoreFilePath = options.ignoreFilePath ?? path.join(absTarget, '.skillguardignore');
  const ignoreResult = loadIgnoreFile(ignoreFilePath);

  const { skillMdPath, files, unscannedFiles } = walk(absTarget, ignoreResult.patterns);

  if (!skillMdPath && files.length === 0) {
    return {
      target: absTarget,
      findings: [],
      timeouts: [],
      unscannedFiles,
      filesScanned: 0,
      severityThreshold,
      warnings: [
        ...ignoreResult.warnings,
        {
          code: 'no-skill-files-found',
          message: formatWhatWhyFix(
            `No skill files found under "${absTarget}".`,
            'SkillGuard looks for a SKILL.md manifest plus hooks/scripts, and found neither.',
            'Point SkillGuard at a directory that contains a SKILL.md file, e.g. npx skillguard-cli scan ./examples/known-bad-skill'
          ),
        },
      ],
      exitCode: 2,
    };
  }

  const { packs, warnings: packWarnings } = loadRulePacks(rulepacksDir, CORE_VERSION);

  const patternPacks = packs.filter((p) => p.manifest.kind === 'pattern');
  const compiledRules = compileRules(patternPacks);
  const { findings: patternFindings, timedOutFiles } = runRules(files, compiledRules, {
    timeoutMs,
    clock: options.clock,
  });

  const structuralFindings = [];
  const structuralWarnings: typeof packWarnings = [];
  const hasStructuralSg07 = packs.some(
    (p) => p.manifest.category === 'SG07' && p.manifest.kind === 'structural'
  );
  if (hasStructuralSg07 && skillMdPath) {
    // BUGFIX: this read was previously unguarded, unlike every other file
    // read in this module (walker, suppression cache). SKILL.md existing at
    // walk() time doesn't guarantee it's still readable a moment later
    // (permissions change, the file is removed, a race with the scan
    // target being edited concurrently) -- an unguarded throw here would
    // reject scanSkill()'s promise entirely, breaking the documented
    // library contract (a structured ScanResult, not a thrown exception)
    // for programmatic/agent-native callers. The CLI happened to survive it
    // via its own top-level catch-all, which masked this in manual CLI
    // testing.
    try {
      const skillMdContent = fs.readFileSync(skillMdPath, 'utf8');
      const declared = parseFrontmatter(skillMdContent);
      if (declared) {
        const actual = inferActualBehavior(files);
        structuralFindings.push(...diffFrontmatterBehavior(declared, actual));
      }
    } catch (err) {
      structuralWarnings.push({
        code: 'skill-md-unreadable',
        message: formatWhatWhyFix(
          `Could not read "${skillMdPath}" for the SG07 frontmatter/behavior check.`,
          `${(err as Error).message}`,
          'SG07 was skipped for this scan; the rest of the scan still ran. Check the file exists and is readable.'
        ),
      });
    }
  }

  const allFindings = [...patternFindings, ...structuralFindings];

  // Inline suppression: "# skillguard-ignore: SGxx" on the finding's own line
  // or the line directly above it.
  const fileContentCache = new Map<string, string>();
  const suppressedFindings = allFindings.filter((finding) => {
    const absPath = path.join(absTarget, finding.file);
    let content = fileContentCache.get(absPath);
    if (content === undefined) {
      try {
        content = fs.readFileSync(absPath, 'utf8');
      } catch {
        content = '';
      }
      fileContentCache.set(absPath, content);
    }
    return !isInlineSuppressed(content, finding.line, finding.category);
  });

  const exitCode = suppressedFindings.some((f) => meetsThreshold(f.severity, severityThreshold))
    ? 1
    : 0;

  return {
    target: absTarget,
    findings: suppressedFindings,
    timeouts: timedOutFiles,
    unscannedFiles,
    filesScanned: files.length,
    severityThreshold,
    warnings: [...ignoreResult.warnings, ...packWarnings, ...structuralWarnings],
    exitCode,
  };
}
