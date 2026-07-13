import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { walk } from './walker';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-walker-'));
}

describe('walker', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('finds SKILL.md and hooks/scripts under the target', () => {
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: x\n---\n');
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'install.sh'), '#!/bin/bash\necho hi\n');
    fs.writeFileSync(path.join(dir, 'hooks', 'run.py'), 'print("hi")\n');

    const result = walk(dir);

    expect(result.skillMdPath).toBe(path.join(dir, 'SKILL.md'));
    expect(result.files.map((f) => f.relPath).sort()).toEqual(['hooks/install.sh', 'hooks/run.py']);
    expect(result.files.find((f) => f.relPath === 'hooks/install.sh')?.language).toBe('shell');
    expect(result.files.find((f) => f.relPath === 'hooks/run.py')?.language).toBe('python');
  });

  it('applies .skillguardignore-style globs to suppress matched files', () => {
    fs.mkdirSync(path.join(dir, 'hooks'));
    fs.writeFileSync(path.join(dir, 'hooks', 'keep.js'), 'console.log(1)\n');
    fs.writeFileSync(path.join(dir, 'hooks', 'skip.js'), 'console.log(2)\n');

    const result = walk(dir, ['hooks/skip.js']);

    expect(result.files.map((f) => f.relPath)).toEqual(['hooks/keep.js']);
  });

  it('returns no skill.md and no files for an empty directory', () => {
    const result = walk(dir);
    expect(result.skillMdPath).toBeNull();
    expect(result.files).toEqual([]);
  });

  it('reports unrecognized languages under hooks/scripts as unscanned rather than silently dropping them', () => {
    fs.mkdirSync(path.join(dir, 'scripts'));
    fs.writeFileSync(path.join(dir, 'scripts', 'tool.rb'), 'puts "hi"\n');

    const result = walk(dir);

    expect(result.files).toEqual([]);
    expect(result.unscannedFiles).toEqual(['scripts/tool.rb']);
  });

  it('ignores node_modules and .git directories', () => {
    fs.mkdirSync(path.join(dir, 'node_modules'));
    fs.writeFileSync(path.join(dir, 'node_modules', 'x.js'), 'console.log(1)\n');
    fs.mkdirSync(path.join(dir, '.git'));
    fs.writeFileSync(path.join(dir, '.git', 'y.js'), 'console.log(1)\n');

    const result = walk(dir);
    expect(result.files).toEqual([]);
  });
});
