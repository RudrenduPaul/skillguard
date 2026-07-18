import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadStructuralAnalyzers } from './index';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-structural-'));
}

function writeFile(dir: string, name: string, content: string): void {
  fs.writeFileSync(path.join(dir, name), content);
}

describe('scan/structural loadStructuralAnalyzers', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('loads a valid analyzer module', () => {
    writeFile(
      dir,
      'sg99.js',
      "exports.category = 'SG99';\nexports.analyze = (ctx) => [{ ruleId: 'sg99-test', category: 'SG99', severity: 'LOW', message: 'ok', file: ctx.skillMdPath, line: 1 }];\n"
    );

    const { analyzers, warnings } = loadStructuralAnalyzers(dir);

    expect(warnings).toEqual([]);
    expect(analyzers).toHaveLength(1);
    expect(analyzers[0].category).toBe('SG99');
    expect(
      analyzers[0].analyze({
        skillMdPath: '/tmp/SKILL.md',
        skillMdContent: '',
        files: [],
        absTarget: '/tmp',
      })
    ).toHaveLength(1);
  });

  it('skips index.js and *.test.js without warning', () => {
    writeFile(dir, 'index.js', "exports.category = 'SHOULD_NOT_LOAD';\nexports.analyze = () => [];\n");
    writeFile(
      dir,
      'sg99.test.js',
      "exports.category = 'SHOULD_NOT_LOAD_EITHER';\nexports.analyze = () => [];\n"
    );

    const { analyzers, warnings } = loadStructuralAnalyzers(dir);

    expect(analyzers).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it('ignores non-.js/.ts files silently', () => {
    writeFile(dir, 'README.txt', 'not an analyzer');

    const { analyzers, warnings } = loadStructuralAnalyzers(dir);

    expect(analyzers).toEqual([]);
    expect(warnings).toEqual([]);
  });

  it('a module that throws while loading is skipped with a structural-analyzer-invalid warning, and other valid modules still load', () => {
    writeFile(dir, 'broken.js', "throw new Error('boom during load');\n");
    writeFile(dir, 'sg99.js', "exports.category = 'SG99';\nexports.analyze = () => [];\n");

    const { analyzers, warnings } = loadStructuralAnalyzers(dir);

    expect(analyzers).toHaveLength(1);
    expect(analyzers[0].category).toBe('SG99');
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('structural-analyzer-invalid');
    expect(warnings[0].message).toContain('WHAT:');
    expect(warnings[0].message).toContain('boom during load');
  });

  it('a module missing the category/analyze contract is skipped with a structural-analyzer-invalid warning', () => {
    writeFile(dir, 'bad-shape.js', "exports.category = 42;\nexports.analyze = 'not a function';\n");

    const { analyzers, warnings } = loadStructuralAnalyzers(dir);

    expect(analyzers).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('structural-analyzer-invalid');
    expect(warnings[0].message).toContain('WHAT:');
  });

  it('an unreadable directory produces a structural-analyzers-dir-unreadable warning instead of throwing', () => {
    const missingDir = path.join(dir, 'does-not-exist');

    const { analyzers, warnings } = loadStructuralAnalyzers(missingDir);

    expect(analyzers).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('structural-analyzers-dir-unreadable');
    expect(warnings[0].message).toContain('WHAT:');
  });

  // NOTE: the default `dir ?? __dirname` argument (exercised at production
  // runtime against the compiled dist/scan/structural/*.js output) is not
  // covered here, because loadStructuralAnalyzers() loads modules via
  // require(), which cannot parse raw uncompiled .ts source -- there is no
  // build step ahead of `vitest run`. sg07.ts's own logic is still fully
  // covered: src/ast/frontmatter-behavior-diff.test.ts unit-tests the
  // functions it wraps, and this suite's "loads a valid analyzer module"
  // case above proves the require()+contract-check dispatch mechanism
  // itself against realistic compiled-JS fixtures.
});
