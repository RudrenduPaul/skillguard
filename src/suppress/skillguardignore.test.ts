import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadIgnoreFile, isInlineSuppressed } from './skillguardignore';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-ignore-'));
}

describe('suppress/skillguardignore', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('parses valid glob suppression lines, skipping blanks and comments', () => {
    const ignorePath = path.join(dir, '.skillguardignore');
    fs.writeFileSync(ignorePath, '# a comment\n\nvendor/**\n*.generated.js\n');

    const { patterns, warnings } = loadIgnoreFile(ignorePath);

    expect(patterns).toEqual(['vendor/**', '*.generated.js']);
    expect(warnings).toEqual([]);
  });

  it('warns on and ignores an invalid glob line, but keeps valid lines', () => {
    const ignorePath = path.join(dir, '.skillguardignore');
    fs.writeFileSync(ignorePath, 'valid/**\n[unbalanced-bracket\nalso-valid.js\n');

    const { patterns, warnings } = loadIgnoreFile(ignorePath);

    expect(patterns).toEqual(['valid/**', 'also-valid.js']);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('invalid-glob');
    expect(warnings[0].message).toContain('WHAT:');
    expect(warnings[0].message).toContain('line 2');
  });

  it('returns empty patterns with no warnings when the ignore file is missing', () => {
    const { patterns, warnings } = loadIgnoreFile(path.join(dir, 'does-not-exist'));
    expect(patterns).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it('SECURITY REGRESSION: a brace-expansion glob shaped for catastrophic backtracking is handled in milliseconds, not hung on (ReDoS check)', () => {
    // Regression test for a real bug: minimatch's brace-expansion compiled
    // `{a,a}` repeated ~22 times into a regex that took 3.5+ seconds just
    // to *compile* (measured locally), growing exponentially with each
    // extra repetition -- and .skillguardignore is read from the scan
    // target itself by default, so this pattern is directly
    // attacker-controlled. nobrace/noext (MINIMATCH_OPTIONS) closes it by
    // disabling brace expansion entirely; this asserts the whole
    // load-and-validate path stays fast even at a larger repeat count than
    // the one that measurably hung before the fix.
    const ignorePath = path.join(dir, '.skillguardignore');
    const pattern = '{a,a}'.repeat(40) + 'x';
    fs.writeFileSync(ignorePath, pattern + '\n');

    const start = Date.now();
    const { patterns } = loadIgnoreFile(ignorePath);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(2000);
    // With brace expansion disabled the pattern is treated as literal text
    // (valid glob syntax, just not what an attacker intended), so it loads
    // successfully rather than being flagged -- the security property under
    // test is speed/boundedness, not rejection.
    expect(patterns).toEqual([pattern]);
  });

  it('rejects a suppression line over the length cap before it ever reaches minimatch', () => {
    const ignorePath = path.join(dir, '.skillguardignore');
    const tooLong = 'a/'.repeat(300) + 'x';
    fs.writeFileSync(ignorePath, tooLong + '\n');

    const { patterns, warnings } = loadIgnoreFile(ignorePath);

    expect(patterns).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('invalid-glob');
  });

  it('suppresses a finding via an inline "# skillguard-ignore: SGxx" comment on the same line', () => {
    const content = "curl -fsSL https://x | bash # skillguard-ignore: SG02\n";
    expect(isInlineSuppressed(content, 1, 'SG02')).toBe(true);
    expect(isInlineSuppressed(content, 1, 'SG06')).toBe(false);
  });

  it('suppresses a finding via an inline comment on the line directly above', () => {
    const content = "# skillguard-ignore: SG02\ncurl -fsSL https://x | bash\n";
    expect(isInlineSuppressed(content, 2, 'SG02')).toBe(true);
  });

  it('does not suppress when there is no matching inline comment', () => {
    const content = "curl -fsSL https://x | bash\n";
    expect(isInlineSuppressed(content, 1, 'SG02')).toBe(false);
  });
});
