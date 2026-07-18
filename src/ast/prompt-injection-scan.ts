/**
 * SG08 — prompt-injection-via-skill-content. Scans SKILL.md's markdown body
 * (the instructional text a host agent reads and follows, distinct from the
 * YAML frontmatter SG07 already covers) for phrasing and encoding tricks
 * commonly used to override a host agent's system prompt or hijack its tool
 * routing (a read-only structural scan — this module never executes
 * anything from the scan target, only reads file bytes and pattern-matches,
 * same invariant as src/ast/frontmatter-behavior-diff.ts and
 * src/scan/semgrep-runner.ts).
 *
 * HONESTY NOTE (matches SG05's documented false-negative-rate discipline —
 * see rulepacks/sg05-obfuscated-payloads/rules.yml's header comment): this
 * is heuristic, regex-based pattern matching against known phrasing and
 * known hiding techniques. It is NOT semantic or LLM-based analysis. A
 * sufficiently novel or paraphrased injection attempt will not match these
 * fixed patterns and will produce a false negative. These checks catch
 * known, common instruction-override idioms and known text-hiding tricks —
 * they are best-effort coverage, not a complete answer to prompt injection.
 */

import type { Finding, Severity } from '../types';

const FRONTMATTER_RE = /^---\r?\n[\s\S]*?\r?\n---\r?\n?/;

/**
 * Strips SKILL.md's leading YAML frontmatter block (if present) and returns
 * the remaining markdown body, plus how many lines the frontmatter block
 * consumed so callers can translate a match offset inside `body` back into
 * a 1-based line number in the original, full file.
 */
export function splitFrontmatter(content: string): { body: string; offsetLines: number } {
  const match = FRONTMATTER_RE.exec(content);
  if (!match || match.index !== 0) {
    return { body: content, offsetLines: 0 };
  }
  const consumed = match[0];
  let offsetLines = 0;
  for (let i = 0; i < consumed.length; i++) {
    if (consumed.charCodeAt(i) === 10) offsetLines++;
  }
  return { body: content.slice(consumed.length), offsetLines };
}

/** 1-based line number of `index` within `text`. Mirrors frontmatter-behavior-diff.ts's firstMatchLine helper. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

/** All non-overlapping matches of `re` against `text`, forcing the global flag on regardless of how `re` was authored. */
function findAllMatches(text: string, re: RegExp): RegExpExecArray[] {
  const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
  const globalRe = new RegExp(re.source, flags);
  const matches: RegExpExecArray[] = [];
  let m: RegExpExecArray | null;
  while ((m = globalRe.exec(text)) !== null) {
    matches.push(m);
    if (m[0].length === 0) globalRe.lastIndex++;
  }
  return matches;
}

export interface InjectionPatternRule {
  ruleId: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

/**
 * Direct instruction-override phrasing. HIGH: this wording, if followed by
 * the host agent, directly overrides its system prompt or hides behavior
 * from the user — a confirmed injection *attempt* even though whether the
 * host agent actually complies is outside this static scanner's reach.
 */
export const OVERRIDE_PATTERN_RULES: InjectionPatternRule[] = [
  {
    ruleId: 'sg08-ignore-prior-instructions',
    regex: /\bignore\s+(?:(?:all|previous|prior)\s+){1,2}instructions\b/gi,
    severity: 'HIGH',
    message:
      'SKILL.md body text instructs the reader to ignore its prior/system instructions — a direct prompt-injection phrasing used to override a host agent\'s system prompt.',
  },
  {
    ruleId: 'sg08-disregard-system-prompt',
    regex: /\bdisregard\s+(your|the)\s+system\s+prompt\b/gi,
    severity: 'HIGH',
    message:
      'SKILL.md body text instructs the reader to disregard its system prompt — a direct prompt-injection phrasing used to override a host agent\'s system prompt.',
  },
  {
    ruleId: 'sg08-fake-mode-switch',
    regex: /\byou\s+are\s+now\s+in\s+(developer|debug|unrestricted)\s+mode\b/gi,
    severity: 'HIGH',
    message:
      'SKILL.md body text claims the host agent is now in developer/debug/unrestricted mode — a common phrasing used to trick an agent into bypassing its normal safety behavior.',
  },
  {
    ruleId: 'sg08-reveal-system-prompt',
    regex: /\breveal\s+your\s+(system\s+prompt|instructions)\b/gi,
    severity: 'HIGH',
    message:
      'SKILL.md body text instructs the reader to reveal its system prompt or instructions — a common prompt-extraction phrasing.',
  },
  {
    ruleId: 'sg08-hide-action-from-user',
    regex: /\bdo\s+not\s+(tell|inform|mention\s+to)\s+the\s+user\b/gi,
    severity: 'HIGH',
    message:
      'SKILL.md body text instructs the reader not to tell/inform/mention something to the user — a common phrasing used to hide an agent\'s actions from the person it is working for.',
  },
];

/**
 * Invisible/zero-width Unicode characters commonly used to hide injected
 * text from a human reviewer skimming the rendered markdown (the text is
 * still there for an LLM tokenizer to read): zero-width space/joiner/
 * non-joiner, word joiner, BOM, soft hyphen, bidi-override controls, and
 * the Unicode "tag" block (U+E0000-U+E007F) — a range with no legitimate
 * use in skill documentation that has been used in real-world prompt-
 * injection payloads to smuggle hidden instructions past visual review.
 */
const INVISIBLE_CHARS_RE =
  /[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/gu;

/**
 * Suspiciously large base64-like encoded blocks embedded directly in
 * SKILL.md's own instructional text (distinct from SG05, which scans
 * *script* files for base64-into-eval/exec idioms — this is about encoded
 * payloads hidden inside the markdown the agent reads as instructions).
 * Length 60+ of pure base64-alphabet characters is an arbitrary but
 * deliberately conservative threshold — short base64 strings (short
 * tokens, sample IDs) are common and not by themselves suspicious.
 */
const BASE64_BLOCK_RE = /[A-Za-z0-9+/]{60,}={0,2}/g;

function scanOverridePatterns(body: string, offsetLines: number): Finding[] {
  const findings: Finding[] = [];
  for (const rule of OVERRIDE_PATTERN_RULES) {
    for (const match of findAllMatches(body, rule.regex)) {
      findings.push({
        ruleId: rule.ruleId,
        category: 'SG08',
        severity: rule.severity,
        message: rule.message,
        file: '',
        line: lineAt(body, match.index) + offsetLines,
      });
    }
  }
  return findings;
}

function scanInvisibleChars(body: string, offsetLines: number): Finding[] {
  const matches = findAllMatches(body, INVISIBLE_CHARS_RE);
  const seenLines = new Set<number>();
  const findings: Finding[] = [];
  for (const match of matches) {
    const line = lineAt(body, match.index) + offsetLines;
    // Dedupe to one finding per line: a single hiding technique often
    // repeats an invisible character between every letter of a phrase,
    // and reporting each individually would flood the finding list
    // without adding signal beyond "this line contains hidden characters".
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    findings.push({
      ruleId: 'sg08-hidden-unicode-characters',
      category: 'SG08',
      severity: 'MEDIUM',
      message:
        'SKILL.md body text contains invisible/zero-width Unicode characters, which can be used to hide injected instructions from a human reviewing the rendered markdown. Flagged for manual review — this is not by itself a confirmed exploit.',
      file: '',
      line,
    });
  }
  return findings;
}

function scanBase64Blocks(body: string, offsetLines: number): Finding[] {
  const findings: Finding[] = [];
  for (const match of findAllMatches(body, BASE64_BLOCK_RE)) {
    findings.push({
      ruleId: 'sg08-encoded-block-in-instructions',
      category: 'SG08',
      severity: 'MEDIUM',
      message:
        'SKILL.md body text contains a suspiciously large base64-like encoded block embedded directly in the skill\'s instructional text. Flagged for manual review — this is not by itself a confirmed exploit.',
      file: '',
      line: lineAt(body, match.index) + offsetLines,
    });
  }
  return findings;
}

/**
 * Scans SKILL.md's markdown body (frontmatter stripped) for the three
 * prompt-injection categories documented above. `file` is left empty on
 * every returned Finding — the caller (src/scan/structural/sg08.ts) fills
 * it in with the SKILL.md path relative to the scan target, since this
 * module has no notion of the scan target's root.
 */
export function scanPromptInjection(skillMdContent: string): Finding[] {
  const { body, offsetLines } = splitFrontmatter(skillMdContent);
  return [
    ...scanOverridePatterns(body, offsetLines),
    ...scanInvisibleChars(body, offsetLines),
    ...scanBase64Blocks(body, offsetLines),
  ];
}
