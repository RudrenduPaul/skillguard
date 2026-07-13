import { z } from 'zod';
import type { Finding, ScanResult, Severity } from '../types';

/**
 * Three output formats:
 *  - human  (default for the bare CLI)
 *  - json   (schema-validated shape, see JsonOutputSchema below)
 *  - sarif  (valid SARIF 2.1.0 for GitHub code-scanning upload — the default
 *            the bundled GitHub Action invokes the CLI with, see action.yml)
 */

const SARIF_TOOL_NAME = 'SkillGuard';
const SARIF_TOOL_VERSION = '0.1.0';
const SARIF_INFO_URI = 'https://github.com/RudrenduPaul/skillguard';

export const JsonOutputSchema = z.object({
  target: z.string(),
  filesScanned: z.number(),
  severityThreshold: z.enum(['HIGH', 'MEDIUM', 'LOW']),
  exitCode: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  summary: z.object({
    HIGH: z.number(),
    MEDIUM: z.number(),
    LOW: z.number(),
  }),
  findings: z.array(
    z.object({
      ruleId: z.string(),
      category: z.string(),
      severity: z.enum(['HIGH', 'MEDIUM', 'LOW']),
      message: z.string(),
      file: z.string(),
      line: z.number(),
      snippet: z.string().optional(),
    })
  ),
  timeouts: z.array(z.string()),
  unscannedFiles: z.array(z.string()),
  warnings: z.array(z.object({ code: z.string(), message: z.string() })),
});

export type JsonOutput = z.infer<typeof JsonOutputSchema>;

function summarize(findings: Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const finding of findings) summary[finding.severity]++;
  return summary;
}

export function toJsonOutput(result: ScanResult): JsonOutput {
  return {
    target: result.target,
    filesScanned: result.filesScanned,
    severityThreshold: result.severityThreshold,
    exitCode: result.exitCode,
    summary: summarize(result.findings),
    findings: result.findings,
    timeouts: result.timeouts,
    unscannedFiles: result.unscannedFiles,
    warnings: result.warnings,
  };
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(toJsonOutput(result), null, 2);
}

export function formatHuman(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`SkillGuard scan: ${result.target}`);
  lines.push(`Files scanned: ${result.filesScanned}`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No findings.');
  } else {
    const bySeverity = summarize(result.findings);
    lines.push(
      `Findings: ${result.findings.length} (HIGH: ${bySeverity.HIGH}, MEDIUM: ${bySeverity.MEDIUM}, LOW: ${bySeverity.LOW})`
    );
    lines.push('');
    for (const finding of result.findings) {
      lines.push(`[${finding.severity}] ${finding.category} ${finding.file}:${finding.line}`);
      lines.push(`  ${finding.ruleId} — ${finding.message}`);
      if (finding.snippet) lines.push(`  > ${finding.snippet}`);
      lines.push('');
    }
  }

  if (result.timeouts.length > 0) {
    lines.push(`[TIMEOUT] files that exceeded the per-file scan timeout (scan continued):`);
    for (const file of result.timeouts) lines.push(`  - ${file}`);
    lines.push('');
  }

  if (result.unscannedFiles.length > 0) {
    lines.push('Unscanned files (unsupported language, not silently skipped):');
    for (const file of result.unscannedFiles) lines.push(`  - ${file}`);
    lines.push('');
  }

  if (result.warnings.length > 0) {
    lines.push('Warnings:');
    for (const warning of result.warnings) {
      lines.push(
        warning.message
          .split('\n')
          .map((l) => `  ${l}`)
          .join('\n')
      );
    }
    lines.push('');
  }

  lines.push(
    `Result: ${result.exitCode === 0 ? 'PASS' : result.exitCode === 1 ? 'FAIL' : 'ERROR'} (exit code ${result.exitCode}, severity threshold ${result.severityThreshold})`
  );

  return lines.join('\n');
}

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'HIGH') return 'error';
  if (severity === 'MEDIUM') return 'warning';
  return 'note';
}

export function formatSarif(result: ScanResult): string {
  const ruleIds = Array.from(new Set(result.findings.map((f) => f.ruleId)));
  const rules = ruleIds.map((ruleId) => {
    const example = result.findings.find((f) => f.ruleId === ruleId)!;
    return {
      id: ruleId,
      name: ruleId,
      shortDescription: { text: example.message },
      properties: { category: example.category, severity: example.severity },
    };
  });

  // BUGFIX: SARIF's `results` array only ever carries findings (matches
  // against a rule + a file location) -- there is no field on a result for
  // a scan-level diagnostic like "target path not found" or "skipped an
  // invalid rule pack." Those surface via `result.warnings` (already
  // WHAT/WHY/FIX formatted), but formatSarif previously dropped that array
  // entirely: a CI engineer running the GitHub Action (which defaults to
  // --format sarif per the locked [redacted]) got a validly-shaped but
  // silently incomplete SARIF file on every scan-level error or warning --
  // exactly the format the Action always uses. SARIF 2.1.0's
  // `invocations[].toolExecutionNotifications` is the spec-correct place
  // for tool diagnostics that are not analysis results, so warnings are
  // surfaced there instead of being dropped.
  const invocation = {
    executionSuccessful: result.exitCode !== 2,
    toolExecutionNotifications: result.warnings.map((warning) => ({
      descriptor: { id: warning.code },
      message: { text: warning.message },
      level: 'warning' as const,
    })),
  };

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: SARIF_TOOL_NAME,
            informationUri: SARIF_INFO_URI,
            version: SARIF_TOOL_VERSION,
            rules,
          },
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: { text: finding.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: { startLine: finding.line },
              },
            },
          ],
        })),
        invocations: [invocation],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

export function formatResult(result: ScanResult, format: 'human' | 'json' | 'sarif'): string {
  if (format === 'json') return formatJson(result);
  if (format === 'sarif') return formatSarif(result);
  return formatHuman(result);
}
