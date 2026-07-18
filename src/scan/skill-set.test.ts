import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanSkillSet, discoverSkillDirs, computeCrossSkillFindings } from './skill-set';
import type { SkillEntry } from '../types';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-skillset-'));
}

function writeSkill(
  root: string,
  name: string,
  skillMdBody: string,
  hookFiles: Record<string, string>
): string {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'SKILL.md'), skillMdBody);
  const hooksDir = path.join(dir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });
  for (const [file, content] of Object.entries(hookFiles)) {
    fs.writeFileSync(path.join(hooksDir, file), content);
  }
  return dir;
}

const CLEAN_SKILL_MD = '---\nname: x\nnetwork: false\nfilesystem: none\n---\n';
const NETWORK_SKILL_MD = '---\nname: net\nnetwork: true\nfilesystem: none\n---\n';
const SANDBOXED_NETWORK_SKILL_MD = '---\nname: net\nnetwork: true\nfilesystem: none\nsandbox: true\n---\n';

const RAW_SOCKET_PY = 'import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n';
const PATH_TRAVERSAL_SH = 'cat ../../../../.env\n';

describe('scan/skill-set discoverSkillDirs()', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('finds immediate subdirectories that contain a SKILL.md', () => {
    writeSkill(dir, 'skill-a', CLEAN_SKILL_MD, {});
    writeSkill(dir, 'skill-b', CLEAN_SKILL_MD, {});
    fs.mkdirSync(path.join(dir, 'not-a-skill'));
    fs.writeFileSync(path.join(dir, 'not-a-skill', 'README.md'), 'hello\n');

    const found = discoverSkillDirs(dir);
    expect(found.map((f) => f.name)).toEqual(['skill-a', 'skill-b']);
    expect(found[0].skillMdPath).toBe(path.join(dir, 'skill-a', 'SKILL.md'));
  });

  it('matches SKILL.md case-insensitively, same convention walker.ts uses', () => {
    const skillDir = path.join(dir, 'skill-a');
    fs.mkdirSync(skillDir);
    fs.writeFileSync(path.join(skillDir, 'skill.md'), CLEAN_SKILL_MD);

    const found = discoverSkillDirs(dir);
    expect(found).toHaveLength(1);
    expect(found[0].name).toBe('skill-a');
  });

  it('ignores .git and node_modules directories even if they somehow contain a SKILL.md', () => {
    writeSkill(dir, '.git', CLEAN_SKILL_MD, {});
    writeSkill(dir, 'node_modules', CLEAN_SKILL_MD, {});
    writeSkill(dir, 'real-skill', CLEAN_SKILL_MD, {});

    const found = discoverSkillDirs(dir);
    expect(found.map((f) => f.name)).toEqual(['real-skill']);
  });

  it('returns an empty array when the directory does not exist', () => {
    expect(discoverSkillDirs(path.join(dir, 'nope'))).toEqual([]);
  });

  it('does not recurse -- a SKILL.md nested two levels deep is not discovered', () => {
    const nested = path.join(dir, 'wrapper', 'actual-skill');
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, 'SKILL.md'), CLEAN_SKILL_MD);

    expect(discoverSkillDirs(dir)).toEqual([]);
  });
});

describe('scan/skill-set scanSkillSet()', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('exit code 2 when the targets directory does not exist', async () => {
    const result = await scanSkillSet(path.join(dir, 'nope'));
    expect(result.exitCode).toBe(2);
    expect(result.warnings[0].code).toBe('targets-dir-not-found');
    expect(result.skills).toEqual([]);
  });

  it('exit code 2 when the targets directory has no skill subdirectories', async () => {
    fs.mkdirSync(path.join(dir, 'just-a-folder'));
    const result = await scanSkillSet(dir);
    expect(result.exitCode).toBe(2);
    expect(result.warnings.some((w) => w.code === 'no-skills-found-in-set')).toBe(true);
  });

  it('scans each skill in the set using the exact same machinery scanSkill() would (per-skill findings preserved)', async () => {
    writeSkill(dir, 'clean-one', CLEAN_SKILL_MD, {
      'greet.js': "console.log('hi');\n",
    });
    writeSkill(dir, 'noisy-one', CLEAN_SKILL_MD, {
      'cleanup.sh': 'rm -rf /etc/config\n',
    });

    const result = await scanSkillSet(dir, { severityThreshold: 'MEDIUM' });
    expect(result.skills).toHaveLength(2);

    const cleanOne = result.skills.find((s) => s.name === 'clean-one')!;
    expect(cleanOne.result.findings).toEqual([]);
    expect(cleanOne.result.exitCode).toBe(0);

    const noisyOne = result.skills.find((s) => s.name === 'noisy-one')!;
    expect(noisyOne.result.findings.some((f) => f.category === 'SG03')).toBe(true);
    expect(noisyOne.result.exitCode).toBe(1);
  });

  it('SG09: a filesystem-read-of-sensitive-paths skill plus a network-egress skill, neither sandboxed, trips a HIGH cross-skill finding at the set level', async () => {
    writeSkill(dir, 'fs-reader', CLEAN_SKILL_MD, { 'read.sh': PATH_TRAVERSAL_SH });
    writeSkill(dir, 'net-sender', NETWORK_SKILL_MD, { 'send.py': RAW_SOCKET_PY });

    const result = await scanSkillSet(dir);

    // Neither skill trips a HIGH finding on its own (both patterns used here
    // are MEDIUM-severity: SG03 path traversal, SG01 raw socket) -- so each
    // skill's own standalone scan would pass cleanly under the default
    // HIGH threshold.
    for (const skill of result.skills) {
      expect(skill.result.exitCode).toBe(0);
    }

    expect(result.findings).toHaveLength(1);
    const sg09 = result.findings[0];
    expect(sg09.category).toBe('SG09');
    expect(sg09.severity).toBe('HIGH');
    expect(sg09.ruleId).toBe('sg09-cross-skill-privilege-chaining');
    expect(sg09.message).toContain('fs-reader');
    expect(sg09.message).toContain('net-sender');
    expect(sg09.file).toBe('fs-reader/hooks/read.sh');

    // The cross-skill finding alone is enough to fail the set-level scan
    // even though every individual skill passed.
    expect(result.exitCode).toBe(1);
  });

  it('SG09 does not fire when only one of the two required capabilities is present in the set', async () => {
    writeSkill(dir, 'fs-reader', CLEAN_SKILL_MD, { 'read.sh': PATH_TRAVERSAL_SH });
    writeSkill(dir, 'harmless', CLEAN_SKILL_MD, { 'greet.js': "console.log('hi');\n" });

    const result = await scanSkillSet(dir);
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('SG09 does not fire when the network-egress skill declares per-skill sandboxing', async () => {
    writeSkill(dir, 'fs-reader', CLEAN_SKILL_MD, { 'read.sh': PATH_TRAVERSAL_SH });
    writeSkill(dir, 'net-sender', SANDBOXED_NETWORK_SKILL_MD, { 'send.py': RAW_SOCKET_PY });

    const result = await scanSkillSet(dir);
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('a clean skill set (no capability findings at all) reports no SG09 finding and exit code 0', async () => {
    writeSkill(dir, 'skill-a', CLEAN_SKILL_MD, { 'greet.js': "console.log('hi');\n" });
    writeSkill(dir, 'skill-b', CLEAN_SKILL_MD, {
      'format.py': "print('hello')\n",
    });

    const result = await scanSkillSet(dir);
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });
});

describe('scan/skill-set computeCrossSkillFindings()', () => {
  function makeEntry(name: string, path_: string, findings: SkillEntry['result']['findings']): SkillEntry {
    return {
      name,
      path: path_,
      result: {
        target: path_,
        findings,
        timeouts: [],
        unscannedFiles: [],
        warnings: [],
        filesScanned: 1,
        severityThreshold: 'HIGH',
        exitCode: 0,
      },
    };
  }

  it('flags the same skill combining both capabilities with a distinct "alone combines" message', () => {
    const dir = makeTempDir();
    try {
      const skillDir = writeSkill(dir, 'combo', CLEAN_SKILL_MD, {});
      const discovered = [
        { name: 'combo', path: skillDir, skillMdPath: path.join(skillDir, 'SKILL.md') },
      ];
      const skills = [
        makeEntry('combo', skillDir, [
          {
            ruleId: 'sg03-path-traversal',
            category: 'SG03',
            severity: 'MEDIUM',
            message: 'traversal',
            file: 'hooks/read.sh',
            line: 3,
          },
          {
            ruleId: 'sg01-raw-socket-python',
            category: 'SG01',
            severity: 'MEDIUM',
            message: 'socket',
            file: 'hooks/send.py',
            line: 5,
          },
        ]),
      ];

      const findings = computeCrossSkillFindings(discovered, skills);
      expect(findings).toHaveLength(1);
      expect(findings[0].message).toContain('alone combines');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns an empty array for an empty skill set', () => {
    expect(computeCrossSkillFindings([], [])).toEqual([]);
  });
});
