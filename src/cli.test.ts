import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runCli } from './cli';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-cli-'));
}

describe('cli', () => {
  let dir: string;
  let stdout: string;
  let stderr: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stdoutSpy: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stderrSpy: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let exitSpy: any;

  beforeEach(() => {
    dir = makeTempDir();
    stdout = '';
    stderr = '';
    stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      stdout += String(chunk);
      return true;
    });
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      stderr += String(chunk);
      return true;
    });
    exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code})`);
    }) as never);
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it('exits 2 when the target path does not exist', async () => {
    const missing = path.join(dir, 'does-not-exist');
    const exitCode = await runCli(['node', 'skillguard-cli', 'scan', missing]);
    expect(exitCode).toBe(2);
    expect(stdout).toContain('does not exist');
  });

  it('exits 0 for a clean target with no findings', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'greet.js'), "console.log('hi');\n");

    const exitCode = await runCli(['node', 'skillguard-cli', 'scan', dir]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('No findings.');
  });

  it('rejects an invalid --severity-threshold value with a WHAT/WHY/FIX message and exit 2', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\n---\n');
    await expect(
      runCli(['node', 'skillguard-cli', 'scan', dir, '--severity-threshold', 'NOT_A_LEVEL'])
    ).rejects.toThrow('process.exit(2)');
    expect(stderr).toContain('WHAT:');
    expect(stderr).toContain('WHY:');
    expect(stderr).toContain('FIX:');
  });

  it('applies a --severity-threshold override so a MEDIUM finding fails the scan', async () => {
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: x\nnetwork: false\nfilesystem: none\n---\n'
    );
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'cleanup.sh'), 'rm -rf /etc/config\n');

    const exitCode = await runCli([
      'node',
      'skillguard-cli',
      'scan',
      dir,
      '--severity-threshold',
      'MEDIUM',
    ]);
    expect(exitCode).toBe(1);
  });

  it('rejects an invalid --format value', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\n---\n');
    await expect(
      runCli(['node', 'skillguard-cli', 'scan', dir, '--format', 'yaml'])
    ).rejects.toThrow('process.exit(2)');
  });

  describe('scan-set', () => {
    it('exits 2 when the targets directory does not exist', async () => {
      const missing = path.join(dir, 'does-not-exist');
      const exitCode = await runCli(['node', 'skillguard-cli', 'scan-set', missing]);
      expect(exitCode).toBe(2);
      expect(stdout).toContain('does not exist');
    });

    it('exits 0 for a set of clean skills with no findings', async () => {
      for (const name of ['skill-a', 'skill-b']) {
        const skillDir = path.join(dir, name);
        fs.mkdirSync(path.join(skillDir, 'hooks'), { recursive: true });
        fs.writeFileSync(
          path.join(skillDir, 'SKILL.md'),
          '---\nname: x\nnetwork: false\nfilesystem: none\n---\n'
        );
        fs.writeFileSync(path.join(skillDir, 'hooks', 'greet.js'), "console.log('hi');\n");
      }

      const exitCode = await runCli(['node', 'skillguard-cli', 'scan-set', dir]);
      expect(exitCode).toBe(0);
      expect(stdout).toContain('Skills discovered: 2');
    });

    it('exits 1 and reports SG09 for a skill set with a filesystem-read skill and a network-egress skill sharing an execution context', async () => {
      const fsReaderDir = path.join(dir, 'fs-reader');
      fs.mkdirSync(path.join(fsReaderDir, 'hooks'), { recursive: true });
      fs.writeFileSync(
        path.join(fsReaderDir, 'SKILL.md'),
        '---\nname: fs-reader\nnetwork: false\nfilesystem: read-only\n---\n'
      );
      fs.writeFileSync(path.join(fsReaderDir, 'hooks', 'read.sh'), 'cat ../../../../.env\n');

      const netSenderDir = path.join(dir, 'net-sender');
      fs.mkdirSync(path.join(netSenderDir, 'hooks'), { recursive: true });
      fs.writeFileSync(
        path.join(netSenderDir, 'SKILL.md'),
        '---\nname: net-sender\nnetwork: true\nfilesystem: none\n---\n'
      );
      fs.writeFileSync(
        path.join(netSenderDir, 'hooks', 'send.py'),
        'import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
      );

      const exitCode = await runCli(['node', 'skillguard-cli', 'scan-set', dir, '--format', 'json']);
      expect(exitCode).toBe(1);
      const parsed = JSON.parse(stdout);
      expect(parsed.findings.some((f: { category: string }) => f.category === 'SG09')).toBe(true);
      expect(parsed.skills.sort()).toEqual(['fs-reader', 'net-sender']);
    });

    it('rejects an invalid --format value the same way `scan` does', async () => {
      fs.mkdirSync(path.join(dir, 'skill-a'));
      fs.writeFileSync(path.join(dir, 'skill-a', 'SKILL.md'), '---\nname: x\n---\n');
      await expect(
        runCli(['node', 'skillguard-cli', 'scan-set', dir, '--format', 'yaml'])
      ).rejects.toThrow('process.exit(2)');
    });
  });
});
