import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding, ScanWarning } from '../../types';
import type { ScannableFile } from '../../walker';
import { formatWhatWhyFix } from '../../errors';

/**
 * The structural-analyzer plugin contract: mirrors rulepacks/loader.ts's
 * directory-scan + fail-soft philosophy, but for structural checks (logic
 * that needs a parsed view of SKILL.md plus the script set together, not a
 * single-file pattern match — see rulepacks/sg07-frontmatter-spoofing/
 * pack.json for what a "structural" rule-pack manifest looks like).
 *
 * Each file dropped into this directory (other than this index and any
 * *.test.* files) is a self-contained analyzer module exporting a `category`
 * string constant and an `analyze(ctx)` function returning `Finding[]`. This
 * is true runtime directory discovery, not a static registry — a future
 * SG08/SG09/SG10 analyzer is added by dropping in one new file here, with
 * zero edits to this file or any other shared file.
 *
 * TRUST NOTE: this differs from src/scan/semgrep-runner.ts's invariant
 * ("never eval()s, require()s, or dynamically imports anything read from the
 * scan target"). That invariant is about the untrusted third-party skill
 * being scanned. This directory is first-party, bundled skillguard-cli code
 * (or an explicit, deliberate caller-supplied override, same trust model as
 * ScanOptions.rulepacksDir) — never scan-target content — so loading and
 * executing its modules is the intended mechanism, not a violation of that
 * invariant.
 *
 * Read-only contract: analyzers receive only read-only inputs (SKILL.md
 * content already read, the scannable file list, the resolved target path)
 * and must never execute anything from the scan target — the same invariant
 * documented in src/ast/frontmatter-behavior-diff.ts's header comment.
 */

export interface StructuralAnalysisContext {
  /** Absolute path to the scan target's SKILL.md. */
  skillMdPath: string;
  /** Already-read SKILL.md content, shared across every matched analyzer. */
  skillMdContent: string;
  /** The scannable hooks/scripts discovered under the scan target. */
  files: ScannableFile[];
  /** Absolute, resolved scan target path. */
  absTarget: string;
}

export interface StructuralAnalyzer {
  category: string;
  analyze: (ctx: StructuralAnalysisContext) => Finding[];
}

export interface LoadStructuralAnalyzersResult {
  analyzers: StructuralAnalyzer[];
  warnings: ScanWarning[];
}

function isAnalyzerFile(fileName: string): boolean {
  if (fileName === 'index.js' || fileName === 'index.ts' || fileName === 'index.d.ts') {
    return false;
  }
  if (/\.test\.(js|ts)$/.test(fileName) || fileName.endsWith('.test.d.ts')) return false;
  if (fileName.endsWith('.d.ts')) return false;
  return fileName.endsWith('.js') || fileName.endsWith('.ts');
}

function invalidAnalyzerWarning(fileName: string, filePath: string, why: string): ScanWarning {
  return {
    code: 'structural-analyzer-invalid',
    message: formatWhatWhyFix(
      `Skipped structural analyzer "${fileName}" — it will not run for this scan.`,
      why,
      `Ensure ${filePath} exports a string \`category\` constant and a function \`analyze(ctx)\`.`
    ),
  };
}

/**
 * Loads every structural analyzer module under `dir` (default: this
 * directory itself via `__dirname`, the same pattern bundledRulepacksDir()
 * in src/scan/index.ts uses for rule packs — when compiled, that resolves
 * to dist/scan/structural/, shipped in the published package alongside
 * dist/). A file that fails to load, or whose exports don't match the
 * `category`/`analyze` contract, is skipped with a warning — the remaining
 * valid analyzers still run (fail-soft, matches loadRulePacks()'s locked
 * behavior). Nothing here ever throws for one bad file.
 *
 * NOTE: this loads modules via `require()`, which only understands
 * already-compiled CommonJS (.js). Against the *compiled* dist output (the
 * real runtime path) this just works. Run against raw uncompiled .ts
 * source it cannot parse TS syntax and every file fails to load — this is
 * why this module's own tests pass an explicit `dir` of plain .js fixture
 * files rather than exercising the default `__dirname` against src/.
 */
export function loadStructuralAnalyzers(dir?: string): LoadStructuralAnalyzersResult {
  const structuralDir = dir ?? __dirname;
  const warnings: ScanWarning[] = [];
  const analyzers: StructuralAnalyzer[] = [];

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(structuralDir, { withFileTypes: true });
  } catch (err) {
    warnings.push({
      code: 'structural-analyzers-dir-unreadable',
      message: formatWhatWhyFix(
        `Could not read the structural analyzers directory "${structuralDir}".`,
        `${(err as Error).message}`,
        'Reinstall skillguard-cli, or pass a valid directory to loadStructuralAnalyzers().'
      ),
    });
    return { analyzers, warnings };
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!isAnalyzerFile(entry.name)) continue;

    const filePath = path.join(structuralDir, entry.name);
    let mod: unknown;
    try {
      // First-party module load (see TRUST NOTE above) — never scan-target content.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      mod = require(filePath);
    } catch (err) {
      warnings.push(invalidAnalyzerWarning(entry.name, filePath, (err as Error).message));
      continue;
    }

    const category = (mod as Record<string, unknown>)?.category;
    const analyze = (mod as Record<string, unknown>)?.analyze;

    if (typeof category !== 'string' || typeof analyze !== 'function') {
      warnings.push(
        invalidAnalyzerWarning(
          entry.name,
          filePath,
          'It does not export a string `category` and a function `analyze`.'
        )
      );
      continue;
    }

    analyzers.push({ category, analyze: analyze as StructuralAnalyzer['analyze'] });
  }

  return { analyzers, warnings };
}
