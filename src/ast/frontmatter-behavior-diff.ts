import { parse as parseYaml } from 'yaml';
import type { ScannableFile } from '../walker';
import type { Finding } from '../types';
import * as fs from 'node:fs';

/**
 * SG07 — frontmatter spoofing. Parses SKILL.md's YAML frontmatter for its
 * declared network/filesystem scope, then compares it against the actual
 * behavior implied by the skill's hooks/scripts (a read-only structural
 * scan — this module never executes anything from the scan target, only
 * reads file bytes and pattern-matches, same invariant as
 * src/scan/semgrep-runner.ts).
 *
 * Declared scope schema (SKILL.md frontmatter):
 *   ---
 *   name: my-skill
 *   network: false          # boolean — does this skill need network access?
 *   filesystem: none        # "none" | "read-only" | "read-write"
 *   ---
 *
 * A mismatch (declared narrower than actual) is a MEDIUM finding per the
 * [redacted]: declared-scope violation without a confirmed
 * exploit path, as distinct from SG02/SG06's confirmed executable impact.
 */

export interface DeclaredScope {
  network: boolean;
  filesystemWrite: boolean;
}

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---/;

export function parseFrontmatter(skillMdContent: string): DeclaredScope | null {
  const match = FRONTMATTER_RE.exec(skillMdContent);
  if (!match) return null;

  let data: unknown;
  try {
    data = parseYaml(match[1]);
  } catch {
    return null;
  }

  if (typeof data !== 'object' || data === null) return null;
  const record = data as Record<string, unknown>;

  const network = record.network === true;
  const filesystem = typeof record.filesystem === 'string' ? record.filesystem : 'none';
  const filesystemWrite = filesystem === 'read-write';

  return { network, filesystemWrite };
}

const NETWORK_EVIDENCE_RE =
  /\b(fetch|axios|http\.request|https\.request|requests\.(get|post|put|delete)|urllib\.request|urlopen|socket\.socket|curl\s|wget\s)\b/i;

const FS_WRITE_EVIDENCE_RE =
  /\b(fs\.writeFile|fs\.writeFileSync|fs\.appendFile|fs\.unlink|open\([^)]*['"]w|os\.remove|os\.rmdir|shutil\.rmtree)\b|>\s*\/|rm\s+-rf/i;

export interface BehaviorEvidence {
  network: boolean;
  filesystemWrite: boolean;
  networkEvidence: { file: string; line: number }[];
  fsEvidence: { file: string; line: number }[];
}

function firstMatchLine(content: string, re: RegExp): number | null {
  const match = re.exec(content);
  if (!match) return null;
  let line = 1;
  for (let i = 0; i < match.index; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

export function inferActualBehavior(scripts: ScannableFile[]): BehaviorEvidence {
  const evidence: BehaviorEvidence = {
    network: false,
    filesystemWrite: false,
    networkEvidence: [],
    fsEvidence: [],
  };

  for (const script of scripts) {
    let content: string;
    try {
      content = fs.readFileSync(script.absPath, 'utf8');
    } catch {
      continue;
    }

    const netLine = firstMatchLine(content, NETWORK_EVIDENCE_RE);
    if (netLine !== null) {
      evidence.network = true;
      evidence.networkEvidence.push({ file: script.relPath, line: netLine });
    }

    const fsLine = firstMatchLine(content, FS_WRITE_EVIDENCE_RE);
    if (fsLine !== null) {
      evidence.filesystemWrite = true;
      evidence.fsEvidence.push({ file: script.relPath, line: fsLine });
    }
  }

  return evidence;
}

export function diffFrontmatterBehavior(
  declared: DeclaredScope,
  actual: BehaviorEvidence
): Finding[] {
  const findings: Finding[] = [];

  if (!declared.network && actual.network) {
    for (const evidence of actual.networkEvidence) {
      findings.push({
        ruleId: 'sg07-network-scope-mismatch',
        category: 'SG07',
        severity: 'MEDIUM',
        message:
          'SKILL.md frontmatter declares "network: false" but this script performs a network call — the declared permission scope does not match actual behavior.',
        file: evidence.file,
        line: evidence.line,
      });
    }
  }

  if (!declared.filesystemWrite && actual.filesystemWrite) {
    for (const evidence of actual.fsEvidence) {
      findings.push({
        ruleId: 'sg07-filesystem-scope-mismatch',
        category: 'SG07',
        severity: 'MEDIUM',
        message:
          'SKILL.md frontmatter does not declare "filesystem: read-write" but this script writes or deletes files — the declared permission scope does not match actual behavior.',
        file: evidence.file,
        line: evidence.line,
      });
    }
  }

  return findings;
}
