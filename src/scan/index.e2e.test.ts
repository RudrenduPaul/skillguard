import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { scanSkill } from './index';

const EXAMPLES_DIR = path.resolve(__dirname, '..', '..', 'examples');

describe('scanSkill end-to-end (bundled rule packs + fixtures)', () => {
  it('a clean skill directory scans with exit code 0 and no findings', async () => {
    const result = await scanSkill(path.join(EXAMPLES_DIR, 'clean-skill'));

    expect(result.exitCode).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it('a second clean skill directory (Python) also scans with exit code 0', async () => {
    const result = await scanSkill(path.join(EXAMPLES_DIR, 'clean-skill-python'));

    expect(result.exitCode).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it('the known-bad-skill fixture scans with exit code 1 and cites a HIGH-severity, file:line finding', async () => {
    const result = await scanSkill(path.join(EXAMPLES_DIR, 'known-bad-skill'));

    expect(result.exitCode).toBe(1);

    const highFindings = result.findings.filter((f) => f.severity === 'HIGH');
    expect(highFindings.length).toBeGreaterThan(0);

    const cited = highFindings[0];
    expect(cited.file).toMatch(/\.(sh|js|py)$/);
    expect(cited.line).toBeGreaterThan(0);

    // Every one of the seven categories should have at least a real rule
    // pack loaded (no warnings about a skipped bundled pack).
    const invalidPackWarnings = result.warnings.filter((w) => w.code === 'invalid-pack');
    expect(invalidPackWarnings).toEqual([]);
  });

  it('the known-bad-skill fixture trips multiple distinct rule categories', async () => {
    const result = await scanSkill(path.join(EXAMPLES_DIR, 'known-bad-skill'));
    const categories = new Set(result.findings.map((f) => f.category));
    expect(categories.size).toBeGreaterThanOrEqual(3);
  });
});
