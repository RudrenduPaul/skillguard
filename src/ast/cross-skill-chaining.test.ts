import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { findSiblingSkillReferences, diffCrossSkillChaining } from './cross-skill-chaining';
import type { ScannableFile } from '../walker';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-sg09-'));
}

describe('ast/cross-skill-chaining findSiblingSkillReferences', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('detects a require() sibling-path reference', () => {
    const scriptPath = path.join(dir, 'setup.js');
    fs.writeFileSync(scriptPath, "const helper = require('../other-skill/lib/helper.js');\n");
    const file: ScannableFile = { absPath: scriptPath, relPath: 'setup.js', language: 'javascript' };

    const refs = findSiblingSkillReferences([file]);
    expect(refs).toEqual([{ siblingName: 'other-skill', file: 'setup.js', line: 1 }]);
  });

  it('detects an import sibling-path reference two levels up', () => {
    const scriptPath = path.join(dir, 'index.ts');
    fs.writeFileSync(scriptPath, "import { run } from '../../deep-sibling/index';\n");
    const file: ScannableFile = { absPath: scriptPath, relPath: 'index.ts', language: 'typescript' };

    const refs = findSiblingSkillReferences([file]);
    expect(refs).toEqual([{ siblingName: 'deep-sibling', file: 'index.ts', line: 1 }]);
  });

  it('detects a Python os.path.join sibling-path reference', () => {
    const scriptPath = path.join(dir, 'run.py');
    fs.writeFileSync(
      scriptPath,
      "import os\nscript = os.path.join('..', 'py-sibling', 'run.sh')\n"
    );
    const file: ScannableFile = { absPath: scriptPath, relPath: 'run.py', language: 'python' };

    const refs = findSiblingSkillReferences([file]);
    expect(refs).toEqual([{ siblingName: 'py-sibling', file: 'run.py', line: 2 }]);
  });

  it('detects a bare shell subprocess-style sibling-path reference', () => {
    const scriptPath = path.join(dir, 'setup.sh');
    fs.writeFileSync(scriptPath, "#!/bin/bash\nbash ../shell-sibling/hooks/setup.sh\n");
    const file: ScannableFile = { absPath: scriptPath, relPath: 'setup.sh', language: 'shell' };

    const refs = findSiblingSkillReferences([file]);
    expect(refs).toEqual([{ siblingName: 'shell-sibling', file: 'setup.sh', line: 2 }]);
  });

  it('finds nothing when there is no sibling-path-shaped reference', () => {
    const scriptPath = path.join(dir, 'plain.js');
    fs.writeFileSync(scriptPath, "console.log('no sibling references here');\n");
    const file: ScannableFile = { absPath: scriptPath, relPath: 'plain.js', language: 'javascript' };

    expect(findSiblingSkillReferences([file])).toEqual([]);
  });
});

describe('ast/cross-skill-chaining diffCrossSkillChaining', () => {
  let parentDir: string;
  let skillADir: string;

  beforeEach(() => {
    parentDir = makeTempDir();
    skillADir = path.join(parentDir, 'skill-a');
    fs.mkdirSync(skillADir);
  });

  afterEach(() => {
    fs.rmSync(parentDir, { recursive: true, force: true });
  });

  it('flags a HIGH finding when the sibling declares broader permissions than skill A', () => {
    const skillBDir = path.join(parentDir, 'other-skill');
    fs.mkdirSync(skillBDir);
    fs.writeFileSync(
      path.join(skillBDir, 'SKILL.md'),
      '---\nname: other-skill\nnetwork: true\nfilesystem: read-write\n---\n'
    );

    const findings = diffCrossSkillChaining(
      { network: false, filesystemWrite: false },
      skillADir,
      [{ siblingName: 'other-skill', file: 'setup.js', line: 3 }]
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'sg09-cross-skill-privilege-escalation',
      category: 'SG09',
      severity: 'HIGH',
      file: 'setup.js',
      line: 3,
    });
    expect(findings[0].message).toContain('other-skill');
    expect(findings[0].message).toContain('network access');
    expect(findings[0].message).toContain('filesystem read-write access');
  });

  it('flags a MEDIUM unverifiable finding when the referenced sibling has no SKILL.md', () => {
    // No 'ghost-skill' directory created at all.
    const findings = diffCrossSkillChaining(
      { network: false, filesystemWrite: false },
      skillADir,
      [{ siblingName: 'ghost-skill', file: 'setup.js', line: 5 }]
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'sg09-unverifiable-cross-skill-reference',
      category: 'SG09',
      severity: 'MEDIUM',
      file: 'setup.js',
      line: 5,
    });
    expect(findings[0].message).toContain('ghost-skill');
  });

  it('flags a MEDIUM unverifiable finding when the sibling directory exists but has no SKILL.md', () => {
    fs.mkdirSync(path.join(parentDir, 'empty-sibling'));

    const findings = diffCrossSkillChaining(
      { network: false, filesystemWrite: false },
      skillADir,
      [{ siblingName: 'empty-sibling', file: 'setup.js', line: 7 }]
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('sg09-unverifiable-cross-skill-reference');
  });

  it('produces no finding when there are no references', () => {
    expect(diffCrossSkillChaining({ network: false, filesystemWrite: false }, skillADir, [])).toEqual(
      []
    );
  });

  it('produces no finding when the sibling declares equal or narrower permissions', () => {
    const skillBDir = path.join(parentDir, 'narrow-skill');
    fs.mkdirSync(skillBDir);
    fs.writeFileSync(
      path.join(skillBDir, 'SKILL.md'),
      '---\nname: narrow-skill\nnetwork: false\nfilesystem: read-only\n---\n'
    );

    const findings = diffCrossSkillChaining(
      { network: true, filesystemWrite: true },
      skillADir,
      [{ siblingName: 'narrow-skill', file: 'setup.js', line: 2 }]
    );

    expect(findings).toEqual([]);
  });

  it('does not flag a self-reference to skill A\'s own directory name', () => {
    const selfName = path.basename(skillADir);
    const findings = diffCrossSkillChaining({ network: false, filesystemWrite: false }, skillADir, [
      { siblingName: selfName, file: 'setup.js', line: 1 },
    ]);

    expect(findings).toEqual([]);
  });
});
