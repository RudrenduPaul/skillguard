import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { scanSkill } from './index';
import { FRONTMATTER_RE } from '../ast/frontmatter-behavior-diff';
import {
  meetsThreshold,
  type Finding,
  type ScanOptions,
  type SkillEntry,
  type SkillSetScanResult,
  type Severity,
} from '../types';
import { formatWhatWhyFix } from '../errors';

/*
 * scanSkillSet() -- SkillGuard's cross-skill entry point, additive alongside
 * scanSkill(). Where scanSkill() vets one skill directory, scanSkillSet()
 * vets a directory whose immediate children are each a skill (a marketplace
 * bundle, a project's .claude/skills/ folder, etc.) and adds one thing a
 * single-skill scan structurally cannot see: SG09, cross-skill privilege
 * chaining -- two skills that are individually clean-looking but, combined
 * in the same unsandboxed execution context, let one skill's filesystem
 * read feed another skill's network egress.
 *
 * Data flow:
 *
 *   targets dir
 *        |
 *        v
 *   discoverSkillDirs()       -> immediate subdirs containing a SKILL.md,
 *        |                       same case-insensitive "SKILL.MD" basename
 *        |                       match walker.ts already uses
 *        v
 *   scanSkill() per subdir    -> the EXISTING single-skill pipeline, reused
 *        |                       verbatim (this module never re-implements
 *        |                       walking, rule loading, or pattern matching)
 *        v
 *   computeCrossSkillFindings() -> SG09: reads each skill's own findings
 *                                   (already produced above) for a network-
 *                                   egress signal and a sensitive-file-read
 *                                   signal, plus each skill's own SKILL.md
 *                                   frontmatter for a "sandbox: true"
 *                                   declaration -- no new pattern engine.
 *
 * NOTE ON RULE-PACK WIRING: this SG09 check deliberately ships with no
 * rulepacks/ manifest and is not registered with src/scan/structural/'s
 * per-skill structural-analyzer registry. That registry's
 * StructuralAnalysisContext is scoped to a single skill's own SKILL.md/
 * files (see its header comment) and is dispatched once per scanSkill()
 * call for every scan -- including plain single-skill `scan` calls -- so a
 * pack.json entry here would make every ordinary scanSkill() see a
 * "structural" SG09 pack with no matching analyzer registered for it
 * (there IS already a different, single-skill-scoped SG09 structural
 * analyzer shipped separately, src/scan/structural/sg09.ts's sibling-path
 * heuristic — a second pack.json under the same category would only add a
 * spurious "structural-analyzer-missing" warning to every single-skill
 * scan). This check only ever runs inside scanSkillSet() itself, which is
 * always an explicit, deliberate call — there is no discoverability need
 * to gate it behind a rule-pack manifest the way per-skill checks are.
 * Findings still carry category "SG09" (same locked taxonomy number,
 * consistent with that sibling-path heuristic — both detect the same
 * underlying cross-skill-privilege-chaining risk, just via different,
 * complementary mechanisms and scopes), with a distinct ruleId
 * ("sg09-cross-skill-privilege-chaining") so the two are never confused.
 */

const DEFAULT_SEVERITY_THRESHOLD: Severity = 'HIGH';

const ALWAYS_IGNORED_DIRS = new Set(['.git', 'node_modules', '.skillguard-cache']);

export interface DiscoveredSkillDir {
  /** The subdirectory's own name under the targets directory. */
  name: string;
  /** Absolute path to the subdirectory. */
  path: string;
  /** Absolute path to the SKILL.md found directly inside it. */
  skillMdPath: string;
}

/**
 * Finds every immediate subdirectory of `targetsDir` that looks like a
 * skill -- i.e. contains a SKILL.md directly inside it (not nested deeper).
 * Uses the exact same case-insensitive "SKILL.MD" basename convention
 * src/walker.ts uses for the single-skill case, so a directory that would
 * be recognized as a skill by `scanSkill()` is recognized the same way
 * here. Returned in a stable (alphabetical by name) order so scan output
 * is deterministic across runs.
 */
export function discoverSkillDirs(targetsDir: string): DiscoveredSkillDir[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(targetsDir, { withFileTypes: true });
  } catch {
    return [];
  }

  const found: DiscoveredSkillDir[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || ALWAYS_IGNORED_DIRS.has(entry.name)) continue;
    const dirPath = path.join(targetsDir, entry.name);

    let children: string[];
    try {
      children = fs.readdirSync(dirPath);
    } catch {
      continue;
    }

    const skillMdName = children.find((name) => name.toUpperCase() === 'SKILL.MD');
    if (skillMdName) {
      found.push({ name: entry.name, path: dirPath, skillMdPath: path.join(dirPath, skillMdName) });
    }
  }

  return found.sort((a, b) => a.name.localeCompare(b.name));
}

// SG09's network-egress signal: either an SG01 (network-mismatch) finding
// -- raw sockets, netcat, /dev/tcp -- or any existing finding whose own
// ruleId/message/snippet already names a network-egress primitive (e.g.
// SG02's "curl-pipe-shell", SG06's "credential-network-send"). This reads
// only findings scanSkill() already produced; it adds no new file-content
// pattern matching of its own.
const NETWORK_EGRESS_KEYWORD_RE = /\b(curl|wget|fetch|requests\.(get|post|put|delete)|axios|urlopen)\b/i;

function isNetworkEgressFinding(finding: Finding): boolean {
  if (finding.category === 'SG01') return true;
  return (
    NETWORK_EGRESS_KEYWORD_RE.test(finding.ruleId) ||
    NETWORK_EGRESS_KEYWORD_RE.test(finding.message) ||
    (!!finding.snippet && NETWORK_EGRESS_KEYWORD_RE.test(finding.snippet))
  );
}

// SG09's sensitive-file-read signal: any SG03 (file-scope-escalation) or
// SG06 (credential-harvesting) finding -- e.g. an SSH private key read, a
// cloud credentials file read, a credential-shaped env var read, or a
// path-traversal/system-path write. Same rationale as above: reuse the
// findings scanSkill() already produced, no parallel detector.
function isSensitiveFileReadFinding(finding: Finding): boolean {
  return finding.category === 'SG03' || finding.category === 'SG06';
}

/**
 * True when a skill's own SKILL.md frontmatter declares `sandbox: true`,
 * meaning that skill is meant to run in its own isolated execution context
 * rather than sharing one with the rest of the set. Deliberately separate
 * from ast/frontmatter-behavior-diff.ts's parseFrontmatter()/DeclaredScope
 * (whose exact shape is asserted via toEqual() in its own test suite) --
 * this only reuses that module's exported FRONTMATTER_RE block-extraction
 * regex, not its declared-scope schema.
 */
function isSandboxDeclared(skillMdContent: string): boolean {
  const match = FRONTMATTER_RE.exec(skillMdContent);
  if (!match) return false;

  let data: unknown;
  try {
    data = parseYaml(match[1]);
  } catch {
    return false;
  }

  if (typeof data !== 'object' || data === null) return false;
  return (data as Record<string, unknown>).sandbox === true;
}

interface CapabilityProfile {
  name: string;
  sandboxed: boolean;
  networkEgressEvidence: Finding | null;
  sensitiveFileReadEvidence: Finding | null;
}

/**
 * SG09 -- cross-skill privilege chaining. Builds a lightweight capability
 * profile per skill from findings scanSkill() already produced (plus each
 * skill's own SKILL.md frontmatter), then checks: does the set contain at
 * least one non-sandboxed skill with a sensitive-file-read capability AND
 * at least one non-sandboxed skill (the same one, or a different one) with
 * a network-egress capability? If so, both run in the same execution
 * context by default (no per-skill sandboxing declared), so the set as a
 * whole can read a sensitive file and exfiltrate it -- a capability
 * neither skill's own standalone scan would have flagged.
 *
 * Reports at most one representative HIGH finding per scanSkillSet() run
 * (the first qualifying pair, in discovery order) rather than every
 * pairwise combination, to keep the signal a single clear flag rather than
 * combinatorial noise across a large skill set.
 */
export function computeCrossSkillFindings(
  discovered: DiscoveredSkillDir[],
  skills: SkillEntry[]
): Finding[] {
  const profiles: CapabilityProfile[] = skills.map((skill, i) => {
    let sandboxed = false;
    try {
      const content = fs.readFileSync(discovered[i].skillMdPath, 'utf8');
      sandboxed = isSandboxDeclared(content);
    } catch {
      sandboxed = false;
    }
    return {
      name: skill.name,
      sandboxed,
      networkEgressEvidence: skill.result.findings.find(isNetworkEgressFinding) ?? null,
      sensitiveFileReadEvidence: skill.result.findings.find(isSensitiveFileReadFinding) ?? null,
    };
  });

  const fsCandidate = profiles.find((p) => !p.sandboxed && p.sensitiveFileReadEvidence);
  const netCandidate = profiles.find((p) => !p.sandboxed && p.networkEgressEvidence);

  if (!fsCandidate || !netCandidate) return [];

  const fsEv = fsCandidate.sensitiveFileReadEvidence!;
  const netEv = netCandidate.networkEgressEvidence!;
  const sameSkill = fsCandidate.name === netCandidate.name;

  const message = sameSkill
    ? `Cross-skill privilege chaining: skill "${fsCandidate.name}" alone combines filesystem-read-of-sensitive-paths ` +
      `capability (${fsEv.ruleId} at ${fsCandidate.name}/${fsEv.file}:${fsEv.line}) and network-egress capability ` +
      `(${netEv.ruleId} at ${netCandidate.name}/${netEv.file}:${netEv.line}) with no per-skill sandboxing declared ` +
      `("sandbox: true" in SKILL.md frontmatter) -- it can read a sensitive credential/file and exfiltrate it over ` +
      `the network on its own, and any other skill sharing its unsandboxed execution context inherits the same risk.`
    : `Cross-skill privilege chaining: skill "${fsCandidate.name}" has filesystem-read-of-sensitive-paths capability ` +
      `(${fsEv.ruleId} at ${fsCandidate.name}/${fsEv.file}:${fsEv.line}) and skill "${netCandidate.name}" has ` +
      `network-egress capability (${netEv.ruleId} at ${netCandidate.name}/${netEv.file}:${netEv.line}). Neither ` +
      `skill declares per-skill sandboxing ("sandbox: true" in SKILL.md frontmatter), so both are assumed to run in ` +
      `the same execution context by default -- combined, this skill set can read a sensitive credential/file with ` +
      `"${fsCandidate.name}" and exfiltrate it over the network with "${netCandidate.name}", a capability neither ` +
      `skill exposes on its own.`;

  return [
    {
      ruleId: 'sg09-cross-skill-privilege-chaining',
      category: 'SG09',
      severity: 'HIGH',
      message,
      file: `${fsCandidate.name}/${fsEv.file}`,
      line: fsEv.line,
    },
  ];
}

export async function scanSkillSet(
  targetsDir: string,
  options: ScanOptions = {}
): Promise<SkillSetScanResult> {
  const severityThreshold = options.severityThreshold ?? DEFAULT_SEVERITY_THRESHOLD;
  const absTargetsDir = path.resolve(targetsDir);

  if (!fs.existsSync(absTargetsDir)) {
    return {
      targetsDir: absTargetsDir,
      skills: [],
      findings: [],
      severityThreshold,
      warnings: [
        {
          code: 'targets-dir-not-found',
          message: formatWhatWhyFix(
            `Targets directory "${absTargetsDir}" does not exist.`,
            'scanSkillSet() scans a directory whose immediate children are each a skill directory (SKILL.md plus hooks/scripts) and needs a real path to start from.',
            'Pass a valid directory path, e.g. npx skillguard-cli scan-set ./my-skills-dir'
          ),
        },
      ],
      exitCode: 2,
    };
  }

  const discovered = discoverSkillDirs(absTargetsDir);

  if (discovered.length === 0) {
    return {
      targetsDir: absTargetsDir,
      skills: [],
      findings: [],
      severityThreshold,
      warnings: [
        {
          code: 'no-skills-found-in-set',
          message: formatWhatWhyFix(
            `No skill subdirectories found under "${absTargetsDir}".`,
            'scanSkillSet() looks for immediate subdirectories that each contain a SKILL.md file, and found none.',
            'Point scanSkillSet at a directory whose immediate children are skill directories, e.g. npx skillguard-cli scan-set ./examples/skill-set-cross-privilege'
          ),
        },
      ],
      exitCode: 2,
    };
  }

  const skills: SkillEntry[] = [];
  for (const d of discovered) {
    // Reuses the EXISTING single-skill scan machinery verbatim -- same
    // options (severity threshold, timeout, ignore file, inline
    // suppression, rule packs dir) applied per skill, exactly as if each
    // subdirectory had been passed to scanSkill() directly.
    const result = await scanSkill(d.path, options);
    skills.push({ name: d.name, path: d.path, result });
  }

  const crossSkillFindings = computeCrossSkillFindings(discovered, skills);

  const anyPerSkillError = skills.some((s) => s.result.exitCode === 2);
  const anyPerSkillFail = skills.some((s) => s.result.exitCode === 1);
  const crossSkillFail = crossSkillFindings.some((f) => meetsThreshold(f.severity, severityThreshold));

  const exitCode: 0 | 1 | 2 = anyPerSkillError ? 2 : anyPerSkillFail || crossSkillFail ? 1 : 0;

  return {
    targetsDir: absTargetsDir,
    skills,
    findings: crossSkillFindings,
    severityThreshold,
    warnings: [],
    exitCode,
  };
}
