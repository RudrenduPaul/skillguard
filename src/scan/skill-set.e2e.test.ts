import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { scanSkillSet } from './skill-set';

const EXAMPLES_DIR = path.resolve(__dirname, '..', '..', 'examples');

describe('scanSkillSet end-to-end (bundled rule packs + fixtures)', () => {
  it('the skill-set-cross-privilege fixture trips SG09 identifying the two combining skills', async () => {
    const result = await scanSkillSet(path.join(EXAMPLES_DIR, 'skill-set-cross-privilege'));

    expect(result.skills.map((s) => s.name).sort()).toEqual(['report-uploader', 'vault-reader']);

    // Neither fixture skill trips a HIGH finding standalone.
    for (const skill of result.skills) {
      expect(skill.result.exitCode).toBe(0);
    }

    expect(result.findings).toHaveLength(1);
    const sg09 = result.findings[0];
    expect(sg09.category).toBe('SG09');
    expect(sg09.severity).toBe('HIGH');
    expect(sg09.message).toContain('vault-reader');
    expect(sg09.message).toContain('report-uploader');

    expect(result.exitCode).toBe(1);
  });

  it('the skill-set-clean fixture scans with exit code 0 and no cross-skill findings', async () => {
    const result = await scanSkillSet(path.join(EXAMPLES_DIR, 'skill-set-clean'));

    expect(result.skills.map((s) => s.name).sort()).toEqual(['formatter', 'greeter']);
    for (const skill of result.skills) {
      expect(skill.result.findings).toEqual([]);
      expect(skill.result.exitCode).toBe(0);
    }
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });
});
