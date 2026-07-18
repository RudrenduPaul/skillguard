/**
 * Shared types for SkillGuard's scan pipeline. Used by both the CLI
 * (src/cli.ts) and the programmatic library export (src/index.ts).
 */

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export type OutputFormat = 'human' | 'json' | 'sarif';

/** SG01 through SG10 — see rulepacks/ for the corresponding rule packs. */
export type RuleCategory =
  | 'SG01'
  | 'SG02'
  | 'SG03'
  | 'SG04'
  | 'SG05'
  | 'SG06'
  | 'SG07'
  | 'SG08'
  | 'SG09'
  | 'SG10';

export interface Finding {
  /** e.g. "sg02-curl-pipe-bash" */
  ruleId: string;
  category: RuleCategory;
  severity: Severity;
  message: string;
  /** Path relative to the scan target. */
  file: string;
  line: number;
  snippet?: string;
}

export interface ScanWarning {
  /** Machine-readable code, e.g. "invalid-pack", "invalid-glob". */
  code: string;
  /** Human-readable WHAT/WHY/FIX formatted message. */
  message: string;
}

export interface ScanResult {
  target: string;
  findings: Finding[];
  /** Files that hit the per-file scan timeout; scan continued past them. */
  timeouts: string[];
  /** Files with a recognized script role but an unsupported language. */
  unscannedFiles: string[];
  warnings: ScanWarning[];
  filesScanned: number;
  severityThreshold: Severity;
  /** 0 = clean, 1 = finding(s) at/above threshold, 2 = target/config error. */
  exitCode: 0 | 1 | 2;
}

export interface ScanOptions {
  /** Minimum severity that causes a non-zero (1) exit code. Default HIGH. */
  severityThreshold?: Severity;
  /** Hard per-file scan timeout in milliseconds. Default 10000. */
  timeoutMs?: number;
  /**
   * Path to a .skillguardignore file. NOT auto-derived from the scan
   * target (security: the target directory is untrusted third-party
   * content SkillGuard exists to vet, so an ignore file shipped inside it
   * must never be trusted implicitly -- only an explicit, deliberate
   * caller-supplied path is honored). Omit to scan with no path
   * suppressions at all.
   */
  ignoreFilePath?: string;
  /** Directory containing first-party (and any local) rule packs. */
  rulepacksDir?: string;
  /**
   * Honor inline `# skillguard-ignore: SGxx` comments found inside the
   * scan target's own files. Default false (security: those comments live
   * inside the exact untrusted content being scanned, so by default
   * nothing in the scan target can silence a finding about itself -- opt
   * in only when the caller already trusts the content, e.g. an author
   * self-scanning their own skill pre-publish).
   */
  allowInlineSuppression?: boolean;
  /** Injectable clock, used by tests to simulate slow scans deterministically. */
  clock?: () => number;
}

/**
 * One skill's individual scan result within a `scanSkillSet()` run. Reuses
 * the exact same `ScanResult` a standalone `scanSkill()` call would return
 * for that same directory -- scanSkillSet() never duplicates the per-skill
 * scan logic, only orchestrates it across a set (see src/scan/skill-set.ts).
 */
export interface SkillEntry {
  /** The skill's own subdirectory name under the scanned targets directory. */
  name: string;
  /** Absolute path to the skill's own directory on disk. */
  path: string;
  /** The identical ScanResult scanSkill(path) would produce standalone. */
  result: ScanResult;
}

/**
 * Result of `scanSkillSet()` -- SkillGuard's cross-skill entry point. Scans
 * every immediate subdirectory of `targetsDir` that looks like a skill
 * (contains a SKILL.md) individually via the existing single-skill
 * machinery, then layers a skill-set-level structural check (SG09 --
 * cross-skill privilege chaining) on top. `findings` here holds only the
 * skill-set-level findings (SG09); each skill's own per-skill findings live
 * on `skills[].result.findings`, unchanged from what scanSkill() would
 * report for that skill in isolation.
 */
export interface SkillSetScanResult {
  targetsDir: string;
  skills: SkillEntry[];
  /** Skill-set-level findings only (currently just SG09). */
  findings: Finding[];
  warnings: ScanWarning[];
  severityThreshold: Severity;
  /** 0 = clean, 1 = finding(s) at/above threshold (per-skill or cross-skill), 2 = target/config error. */
  exitCode: 0 | 1 | 2;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
};

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
