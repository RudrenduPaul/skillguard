import * as fs from 'node:fs';
import * as path from 'node:path';
import { walk } from '../walker';
import { loadRulePacks, CORE_VERSION } from '../rulepacks/loader';
import { compileRules, runRules } from './semgrep-runner';
import { loadIgnoreFile, isInlineSuppressed } from '../suppress/skillguardignore';
import { loadStructuralAnalyzers, type StructuralAnalysisContext } from './structural';
import {
  meetsThreshold,
  type Finding,
  type ScanOptions,
  type ScanResult,
  type ScanWarning,
  type Severity,
} from '../types';
import { formatWhatWhyFix } from '../errors';

/*
 * Data flow (reproduced here for anyone reading this
 * file first):
 *
 *   target path
 *        |
 *        v
 *   .skillguardignore loaded  -> ignore globs (+ warnings for invalid lines).
 *        |                       Only loaded when the caller explicitly
 *        |                       supplies a path -- never auto-derived from
 *        |                       inside the (untrusted) scan target.
 *        v
 *   walker.ts                 -> SKILL.md path, scannable files, unscanned files
 *        |
 *        v
 *   rulepacks/loader.ts       -> loaded packs (invalid packs skipped + warned)
 *        |
 *    +---+-----------------------------+
 *    v                                 v
 *  semgrep-runner.ts (SG01-06,       scan/structural/ (structural analyzer
 *  partial SG05), per-file           registry — directory-discovered, one
 *  timeout enforced                  module per structural category, e.g.
 *                                     SG07's declared-vs-actual-scope diff)
 *    |                                 |
 *    +-----------------+---------------+
 *                       v
 *              inline suppression filter (# skillguard-ignore: SGxx),
 *              off by default -- opt in via allowInlineSuppression
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

  // SECURITY: .skillguardignore is only loaded when the caller explicitly
  // supplies a path (CLI --skillguardignore flag, or the ignoreFilePath
  // library option) -- never auto-derived from inside the scan target. The
  // target directory is untrusted third-party content SkillGuard exists to
  // vet; auto-loading a suppression file that ships inside that exact
  // content would let a malicious skill silence every finding about
  // itself with a single line (verified: a bundled fixture with its own
  // `hooks/**` .skillguardignore line flipped a 5-HIGH-finding scan to a
  // clean exit-0 PASS), which is precisely the "false clean scan" failure
  // mode a security-gate tool cannot have.
  const ignoreResult = options.ignoreFilePath
    ? loadIgnoreFile(options.ignoreFilePath)
    : { patterns: [], warnings: [] };

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

  const structuralFindings: Finding[] = [];
  const structuralWarnings: ScanWarning[] = [];
  const structuralPacks = packs.filter((p) => p.manifest.kind === 'structural');

  if (structuralPacks.length > 0 && skillMdPath) {
    const { analyzers: structuralAnalyzers, warnings: structuralAnalyzerWarnings } =
      loadStructuralAnalyzers();
    structuralWarnings.push(...structuralAnalyzerWarnings);

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
    let skillMdContent: string | null = null;
    try {
      skillMdContent = fs.readFileSync(skillMdPath, 'utf8');
    } catch (err) {
      structuralWarnings.push({
        code: 'skill-md-unreadable',
        message: formatWhatWhyFix(
          `Could not read "${skillMdPath}" for structural checks.`,
          `${(err as Error).message}`,
          'Structural checks were skipped for this scan; the rest of the scan still ran. Check the file exists and is readable.'
        ),
      });
    }

    if (skillMdContent !== null) {
      const ctx: StructuralAnalysisContext = {
        skillMdPath,
        skillMdContent,
        files,
        absTarget,
      };

      for (const pack of structuralPacks) {
        const analyzer = structuralAnalyzers.find((a) => a.category === pack.manifest.category);
        if (!analyzer) {
          structuralWarnings.push({
            code: 'structural-analyzer-missing',
            message: formatWhatWhyFix(
              `No structural analyzer is registered for "${pack.manifest.category}" (declared by rule pack "${pack.manifest.name}").`,
              'The rule pack manifest declares kind "structural" for this category, but no matching analyzer module was found in the structural analyzer registry.',
              'Ensure a structural analyzer module exporting that category exists under src/scan/structural/, or fix/remove the rule pack manifest.'
            ),
          });
          continue;
        }

        try {
          structuralFindings.push(...analyzer.analyze(ctx));
        } catch (err) {
          structuralWarnings.push({
            code: 'structural-analyzer-failed',
            message: formatWhatWhyFix(
              `The "${pack.manifest.category}" structural analyzer threw while analyzing "${absTarget}".`,
              `${(err as Error).message}`,
              'This structural check was skipped for this scan; the rest of the scan still ran.'
            ),
          });
        }
      }
    }
  }

  const allFindings = [...patternFindings, ...structuralFindings];

  // Inline suppression: "# skillguard-ignore: SGxx" on the finding's own
  // line or the line directly above it. SECURITY: off by default (see
  // ScanOptions.allowInlineSuppression) -- these comments live inside the
  // exact untrusted scan-target content being vetted, so by default
  // nothing in that content can silence a finding about itself. Opt in
  // only when the caller already trusts the content (e.g. an author
  // self-scanning their own skill pre-publish).
  const fileContentCache = new Map<string, string>();
  const suppressedFindings = options.allowInlineSuppression
    ? allFindings.filter((finding) => {
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
      })
    : allFindings;

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
