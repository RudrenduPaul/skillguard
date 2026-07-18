import * as path from 'node:path';
import type { Finding } from '../../types';
import type { StructuralAnalysisContext } from './index';
import { scanPromptInjection } from '../../ast/prompt-injection-scan';

/**
 * SG08 structural analyzer — a thin adapter around
 * src/ast/prompt-injection-scan.ts's scanPromptInjection(), exposed through
 * the generic structural-analyzer `category`/`analyze` contract (see
 * src/scan/structural/index.ts). All of the actual detection logic lives in
 * prompt-injection-scan.ts; this file only wires it up and fills in the
 * `file` field (relative to the scan target, matching how SG07's findings
 * report script paths) since prompt-injection-scan.ts has no notion of the
 * scan target's root.
 */

export const category = 'SG08';

export function analyze(ctx: StructuralAnalysisContext): Finding[] {
  const findings = scanPromptInjection(ctx.skillMdContent);
  if (findings.length === 0) return findings;

  const relFile = path.relative(ctx.absTarget, ctx.skillMdPath).split(path.sep).join('/');
  return findings.map((finding) => ({ ...finding, file: relFile }));
}
