import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { analyze, category } from './sg10';
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
    expect(findings[0].severity).toBe('MEDIUM');
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
});
