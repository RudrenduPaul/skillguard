import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadRulePacks } from './loader';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-loader-'));
}

function writePack(
  rulepacksDir: string,
  name: string,
  manifest: unknown,
  rulesYaml?: string
): void {
  const dir = path.join(rulepacksDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'pack.json'), JSON.stringify(manifest, null, 2));
  if (rulesYaml !== undefined) {
    fs.writeFileSync(path.join(dir, 'rules.yml'), rulesYaml);
  }
}

const VALID_RULES_YAML = `
rules:
  - id: test-rule
    message: "test message"
    severity: HIGH
    languages: [javascript]
    regex: "console\\\\.log"
`;

describe('rulepacks/loader', () => {
  let rulepacksDir: string;

  beforeEach(() => {
    rulepacksDir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(rulepacksDir, { recursive: true, force: true });
  });

  it('loads a valid pack.json + rules.yml pack', () => {
    writePack(
      rulepacksDir,
      'sg-test',
      {
        name: 'sg-test',
        version: '0.1.0',
        category: 'SG01',
        minCoreVersion: '0.1.0',
        description: 'test pack',
        kind: 'pattern',
        rulesFile: 'rules.yml',
      },
      VALID_RULES_YAML
    );

    const { packs, warnings } = loadRulePacks(rulepacksDir, '0.1.0');

    expect(warnings).toEqual([]);
    expect(packs).toHaveLength(1);
    expect(packs[0].manifest.name).toBe('sg-test');
    expect(packs[0].rules).toHaveLength(1);
    expect(packs[0].rules[0].id).toBe('test-rule');
  });

  // CRITICAL test: a malformed manifest must be skipped with a warning,
  // and must NOT take down the rest of the scan.
  it('[CRITICAL] skips a malformed manifest with a warning and still loads the remaining valid packs', () => {
    writePack(rulepacksDir, 'broken-pack', { name: 'broken-pack' }); // missing required fields
    writePack(
      rulepacksDir,
      'good-pack',
      {
        name: 'good-pack',
        version: '0.1.0',
        category: 'SG02',
        minCoreVersion: '0.1.0',
        description: 'a valid pack',
        kind: 'pattern',
        rulesFile: 'rules.yml',
      },
      VALID_RULES_YAML
    );

    const { packs, warnings } = loadRulePacks(rulepacksDir, '0.1.0');

    expect(packs).toHaveLength(1);
    expect(packs[0].manifest.name).toBe('good-pack');

    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('invalid-pack');
    expect(warnings[0].message).toContain('WHAT:');
    expect(warnings[0].message).toContain('WHY:');
    expect(warnings[0].message).toContain('FIX:');
    expect(warnings[0].message).toContain('broken-pack');
  });

  it('skips a pack whose pack.json is not valid JSON', () => {
    const dir = path.join(rulepacksDir, 'bad-json-pack');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'pack.json'), '{ not valid json');

    const { packs, warnings } = loadRulePacks(rulepacksDir, '0.1.0');

    expect(packs).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('invalid-pack');
  });

  it('skips a pack whose minCoreVersion exceeds the running core version, with a warning', () => {
    writePack(
      rulepacksDir,
      'future-pack',
      {
        name: 'future-pack',
        version: '0.1.0',
        category: 'SG03',
        minCoreVersion: '99.0.0',
        description: 'requires a future core',
        kind: 'pattern',
        rulesFile: 'rules.yml',
      },
      VALID_RULES_YAML
    );

    const { packs, warnings } = loadRulePacks(rulepacksDir, '0.1.0');

    expect(packs).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0].code).toBe('invalid-pack');
    expect(warnings[0].message).toContain('future-pack');
  });

  it('loads a structural pack (no rulesFile required)', () => {
    writePack(rulepacksDir, 'sg07-frontmatter-spoofing', {
      name: 'sg07-frontmatter-spoofing',
      version: '0.1.0',
      category: 'SG07',
      minCoreVersion: '0.1.0',
      description: 'structural pack',
      kind: 'structural',
    });

    const { packs, warnings } = loadRulePacks(rulepacksDir, '0.1.0');

    expect(warnings).toEqual([]);
    expect(packs).toHaveLength(1);
    expect(packs[0].rules).toEqual([]);
  });
});
