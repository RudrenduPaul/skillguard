import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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

  it('an explicitly-passed .skillguardignore glob suppresses a whole file from scanning', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'cleanup.sh'), 'rm -rf /etc/config\n');
    const ignoreFilePath = path.join(dir, '.skillguardignore');
    fs.writeFileSync(ignoreFilePath, 'hooks/cleanup.sh\n');

    const result = await scanSkill(dir, { severityThreshold: 'MEDIUM', ignoreFilePath });
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it('SECURITY REGRESSION: a .skillguardignore file living inside the scan target is NOT auto-loaded -- a malicious skill cannot suppress findings about itself by default', async () => {
    // Regression test for a real bug: scanSkill() used to default
    // ignoreFilePath to <target>/.skillguardignore, i.e. it auto-trusted a
    // suppression file shipped inside the exact untrusted content being
    // scanned. A malicious skill submission could ship its own
    // .skillguardignore (e.g. a single "hooks/**" line) and flip a scan
    // with real HIGH findings to a clean exit-0 PASS in the default
    // GitHub Action / CI-gate configuration -- a complete bypass of the
    // scanner's core promise. Verified live against the bundled
    // known-bad-skill fixture before this fix (5 HIGH findings -> 0
    // findings, exit 1 -> exit 0) using only a `.skillguardignore` file,
    // no CLI flag.
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'cleanup.sh'), 'rm -rf /etc/config\n');
    fs.writeFileSync(path.join(dir, '.skillguardignore'), 'hooks/cleanup.sh\n');

    // No ignoreFilePath option passed -- this is the default, untrusted path.
    const result = await scanSkill(dir, { severityThreshold: 'MEDIUM' });
    expect(result.findings.some((f) => f.category === 'SG03')).toBe(true);
    expect(result.exitCode).toBe(1);
  });

  it('an inline "# skillguard-ignore: SGxx" comment suppresses just that finding when allowInlineSuppression is explicitly enabled', async () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(
      path.join(dir, 'hooks', 'cleanup.sh'),
      'rm -rf /etc/config # skillguard-ignore: SG03\n'
    );

    const result = await scanSkill(dir, {
      severityThreshold: 'MEDIUM',
      allowInlineSuppression: true,
    });
    expect(result.findings.filter((f) => f.category === 'SG03')).toEqual([]);
  });

  it('SECURITY REGRESSION: an inline "# skillguard-ignore: SGxx" comment is ignored by default -- a malicious skill cannot silence a finding about itself without an explicit opt-in', async () => {
    // Regression test for a real bug: isInlineSuppressed() used to run
    // unconditionally for every finding, reading the comment back out of
    // the exact untrusted file that produced the finding. Since the
    // scanned skill's own author fully controls that file's content, this
    // let a malicious skill annotate its own dangerous lines with a
    // suppression comment and have SkillGuard silently drop the finding --
    // a self-referential bypass of the scanner's own output.
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\nnetwork: false\nfilesystem: none\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(
      path.join(dir, 'hooks', 'cleanup.sh'),
      'rm -rf /etc/config # skillguard-ignore: SG03\n'
    );

    // No allowInlineSuppression option passed -- this is the default.
    const result = await scanSkill(dir, { severityThreshold: 'MEDIUM' });
    expect(result.findings.some((f) => f.category === 'SG03')).toBe(true);
  });

  it('a SKILL.md that becomes unreadable after being found by the walker degrades to a warning instead of throwing (SG07 read guard)', async () => {
    // Regression test for a real bug: the SG07 structural check's read of
    // skillMdPath was the only unguarded fs.readFileSync call in this
    // module (every other read -- walker, suppression cache -- is wrapped
    // in try/catch). An unguarded throw here would reject scanSkill()'s
    // returned promise entirely, breaking the documented library contract
    // (a structured ScanResult, not a thrown exception) for
    // programmatic/agent-native callers -- even though the CLI's own
    // top-level catch-all happened to mask this in manual testing.
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      '---\nname: x\nnetwork: false\nfilesystem: none\n---\n'
    );
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'greet.js'), "console.log('hi');\n");

    const skillMdPath = path.join(dir, 'SKILL.md');
    // process.getuid is undefined on Windows; this suite only runs on POSIX
    // (macOS locally, ubuntu-latest in CI per .github/workflows/ci.yml), and
    // root can bypass a file's own permission bits, so skip rather than
    // false-fail under an unusual runtime.
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    if (isRoot) return;

    fs.chmodSync(skillMdPath, 0o000);
    try {
      const result = await scanSkill(dir);
      expect(result.warnings.some((w) => w.code === 'skill-md-unreadable')).toBe(true);
      expect(result.warnings.find((w) => w.code === 'skill-md-unreadable')?.message).toContain(
        'WHAT:'
      );
    } finally {
      fs.chmodSync(skillMdPath, 0o644);
    }
  });
});
