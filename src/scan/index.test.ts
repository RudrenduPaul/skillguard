import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanSkill } from './index';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-scan-'));
}

describe('scan/index scanSkill()', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('exit code 2 when the target path does not exist', async () => {
    const result = await scanSkill(path.join(dir, 'nope'));
    expect(result.exitCode).toBe(2);
    expect(result.warnings[0].code).toBe('target-not-found');
  });

  it('exit code 2 when the target has neither SKILL.md nor scripts', async () => {
    const result = await scanSkill(dir);
    expect(result.exitCode).toBe(2);
    expect(result.warnings.some((w) => w.code === 'no-skill-files-found')).toBe(true);
  });

  it('a .skillguardignore glob suppresses a whole file from scanning', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'cleanup.sh'), 'rm -rf /etc/config\n');
    fs.writeFileSync(path.join(dir, '.skillguardignore'), 'hooks/cleanup.sh\n');

    const result = await scanSkill(dir, { severityThreshold: 'MEDIUM' });
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('an inline "# skillguard-ignore: SGxx" comment suppresses just that finding', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(
      path.join(dir, 'hooks', 'cleanup.sh'),
      'rm -rf /etc/config # skillguard-ignore: SG03\n'
    );

    const result = await scanSkill(dir, { severityThreshold: 'MEDIUM' });
    expect(result.findings.filter((f) => f.category === 'SG03')).toEqual([]);
  });
});
