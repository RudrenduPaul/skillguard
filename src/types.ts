/**
 * Shared types for SkillGuard's scan pipeline. Used by both the CLI
 * (src/cli.ts) and the programmatic library export (src/index.ts).
 */

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export type OutputFormat = 'human' | 'json' | 'sarif';

/** SG01 through SG07 — see rulepacks/ for the corresponding rule packs. */
export type RuleCategory =
  | 'SG01'
  | 'SG02'
  | 'SG03'
  | 'SG04'
  | 'SG05'
  | 'SG06'
  | 'SG07';

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
  /** Path to a .skillguardignore file. Defaults to <target>/.skillguardignore. */
  ignoreFilePath?: string;
  /** Directory containing first-party (and any local) rule packs. */
  rulepacksDir?: string;
  /** Injectable clock, used by tests to simulate slow scans deterministically. */
  clock?: () => number;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
};

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
