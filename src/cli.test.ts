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
  let stdoutSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

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
});
