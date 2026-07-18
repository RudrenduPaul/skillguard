import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { analyze, category } from './sg10';
import { walk } from '../../walker';
import type { StructuralAnalysisContext } from './index';

function makeCtx(skillMdContent: string): StructuralAnalysisContext {
  const absTarget = '/tmp/skillguard-sg10-fixture';
  return {
    skillMdPath: path.join(absTarget, 'SKILL.md'),
    skillMdContent,
    files: [],
    absTarget,
  };
}

const EXAMPLES_DIR = path.resolve(__dirname, '..', '..', '..', 'examples');

/**
 * Builds a real StructuralAnalysisContext from one of the bundled
 * examples/ fixtures (shared with the Python test suite), via the real
 * walk() -- not an inline string like makeCtx() above. This is the direct,
 * in-process equivalent of an end-to-end scanSkill() run against these
 * fixtures: scan/index.e2e.test.ts can't exercise SG10 through scanSkill()
 * itself, since loadStructuralAnalyzers() only discovers analyzer modules
 * via require() against *compiled* dist output (see the NOTE in that
 * file) -- true of every structural analyzer under vitest's raw-TS test
 * environment, not specific to SG10.
 */
function contextForFixture(fixtureDir: string): StructuralAnalysisContext {
  const absTarget = path.join(EXAMPLES_DIR, fixtureDir);
  const { skillMdPath, files } = walk(absTarget);
  if (!skillMdPath) throw new Error(`fixture ${fixtureDir} has no SKILL.md`);
  return {
    skillMdPath,
    skillMdContent: fs.readFileSync(skillMdPath, 'utf8'),
    files,
    absTarget,
  };
}

describe('scan/structural/sg10', () => {
  it('exports the SG10 category', () => {
    expect(category).toBe('SG10');
  });

  it('flags a declared name closely resembling a known name (edit distance 1-2)', () => {
    const ctx = makeCtx('---\nname: numpi\n---\nbody\n');
    const findings = analyze(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('sg10-typosquat-suspected');
    expect(findings[0].category).toBe('SG10');
    expect(findings[0].severity).toBe('HIGH');
    expect(findings[0].file).toBe('SKILL.md');
    expect(findings[0].line).toBe(2);
    expect(findings[0].message).toContain('numpi');
    expect(findings[0].message).toContain('numpy');
  });

  it('does not flag an exact match to a known name', () => {
    const ctx = makeCtx('---\nname: numpy\n---\nbody\n');
    expect(analyze(ctx)).toEqual([]);
  });

  it('does not flag a name unrelated to anything on the known-names list', () => {
    const ctx = makeCtx('---\nname: my-totally-unrelated-skill-xyz\n---\nbody\n');
    expect(analyze(ctx)).toEqual([]);
  });

  it('produces no findings and does not crash when no name field is declared', () => {
    const ctx = makeCtx('---\nnetwork: false\n---\nbody\n');
    expect(() => analyze(ctx)).not.toThrow();
    expect(analyze(ctx)).toEqual([]);
  });

  it('produces no findings and does not crash when there is no frontmatter at all', () => {
    const ctx = makeCtx('# just a heading\nno frontmatter here\n');
    expect(() => analyze(ctx)).not.toThrow();
    expect(analyze(ctx)).toEqual([]);
  });

  describe('against the bundled examples/ fixtures (shared with the Python test suite)', () => {
    it('flags the typosquat-skill fixture (name "numpi", one edit from "numpy") HIGH, citing SKILL.md', () => {
      const findings = analyze(contextForFixture('typosquat-skill'));

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: 'sg10-typosquat-suspected',
        category: 'SG10',
        severity: 'HIGH',
        file: 'SKILL.md',
      });
      expect(findings[0].line).toBeGreaterThan(0);
      expect(findings[0].message).toContain('numpi');
      expect(findings[0].message).toContain('numpy');
    });

    it('does not flag the known-name-legit-skill fixture (exact match "numpy")', () => {
      expect(analyze(contextForFixture('known-name-legit-skill'))).toEqual([]);
    });

    it('does not flag unrelated, legitimately-named clean fixtures', () => {
      expect(analyze(contextForFixture('clean-skill'))).toEqual([]);
      expect(analyze(contextForFixture('clean-skill-python'))).toEqual([]);
    });

    it('does not flag the known-bad-skill fixture (name "known-bad-skill" is unrelated to any known name)', () => {
      expect(analyze(contextForFixture('known-bad-skill'))).toEqual([]);
    });
  });
});
