import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { analyze, category } from './sg09';
import type { StructuralAnalysisContext } from './index';
import type { ScannableFile } from '../../walker';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-sg09-analyzer-'));
}

function makeCtx(skillADir: string, skillMdContent: string, hookRelPath: string): StructuralAnalysisContext {
  const hookAbsPath = path.join(skillADir, hookRelPath);
  return {
    skillMdPath: path.join(skillADir, 'SKILL.md'),
    skillMdContent,
    files: [{ absPath: hookAbsPath, relPath: hookRelPath, language: 'javascript' } as ScannableFile],
    absTarget: skillADir,
  };
}

describe('scan/structural/sg09 analyze', () => {
  let parentDir: string;
  let skillADir: string;

  beforeEach(() => {
    parentDir = makeTempDir();
    skillADir = path.join(parentDir, 'skill-a');
    fs.mkdirSync(path.join(skillADir, 'hooks'), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(parentDir, { recursive: true, force: true });
  });

  it('exports the SG09 category', () => {
    expect(category).toBe('SG09');
  });

  it('(a) HIGH finding: skill A references sibling skill B with broader declared permissions', () => {
    const skillBDir = path.join(parentDir, 'broad-sibling');
    fs.mkdirSync(skillBDir);
    fs.writeFileSync(
      path.join(skillBDir, 'SKILL.md'),
      '---\nname: broad-sibling\nnetwork: true\nfilesystem: read-write\n---\n'
    );

    fs.writeFileSync(
      path.join(skillADir, 'hooks/setup.js'),
      "const lib = require('../broad-sibling/index.js');\n"
    );

    const ctx = makeCtx(
      skillADir,
      '---\nname: skill-a\nnetwork: false\nfilesystem: none\n---\n',
      'hooks/setup.js'
    );

    const findings = analyze(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('sg09-cross-skill-privilege-escalation');
    expect(findings[0].category).toBe('SG09');
    expect(findings[0].severity).toBe('HIGH');
    expect(findings[0].file).toBe('hooks/setup.js');
  });

  it('(b) MEDIUM finding: skill A references a sibling path with no SKILL.md present', () => {
    fs.writeFileSync(
      path.join(skillADir, 'hooks/setup.js'),
      "const lib = require('../nonexistent-sibling/index.js');\n"
    );

    const ctx = makeCtx(
      skillADir,
      '---\nname: skill-a\nnetwork: false\nfilesystem: none\n---\n',
      'hooks/setup.js'
    );

    const findings = analyze(ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('sg09-unverifiable-cross-skill-reference');
    expect(findings[0].category).toBe('SG09');
    expect(findings[0].severity).toBe('MEDIUM');
    expect(findings[0].file).toBe('hooks/setup.js');
  });

  it('(c) no findings when skill A has no sibling references', () => {
    fs.writeFileSync(path.join(skillADir, 'hooks/setup.js'), "console.log('nothing to see here');\n");

    const ctx = makeCtx(
      skillADir,
      '---\nname: skill-a\nnetwork: false\nfilesystem: none\n---\n',
      'hooks/setup.js'
    );

    expect(analyze(ctx)).toEqual([]);
  });

  it('(c) no findings when the referenced sibling declares equal or narrower permissions', () => {
    const skillBDir = path.join(parentDir, 'narrow-sibling');
    fs.mkdirSync(skillBDir);
    fs.writeFileSync(
      path.join(skillBDir, 'SKILL.md'),
      '---\nname: narrow-sibling\nnetwork: false\nfilesystem: read-only\n---\n'
    );

    fs.writeFileSync(
      path.join(skillADir, 'hooks/setup.js'),
      "const lib = require('../narrow-sibling/index.js');\n"
    );

    const ctx = makeCtx(
      skillADir,
      '---\nname: skill-a\nnetwork: true\nfilesystem: read-write\n---\n',
      'hooks/setup.js'
    );

    expect(analyze(ctx)).toEqual([]);
  });
});
