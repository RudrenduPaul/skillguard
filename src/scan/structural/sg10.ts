import * as path from 'node:path';
import type { Finding } from '../../types';
import type { StructuralAnalysisContext } from './index';
import { parseDeclaredName, loadKnownNames, findTyposquatMatches } from '../../ast/typosquatting-check';

/**
 * SG10 structural analyzer — a thin adapter around
 * src/ast/typosquatting-check.ts's existing parseDeclaredName /
 * loadKnownNames / findTyposquatMatches functions, exposed through the
 * generic structural-analyzer `category`/`analyze` contract (see
 * src/scan/structural/index.ts). All of the actual comparison logic still
 * lives in typosquatting-check.ts; this file only wires it up.
 */

export const category = 'SG10';

export function analyze(ctx: StructuralAnalysisContext): Finding[] {
  const declared = parseDeclaredName(ctx.skillMdContent);
  if (!declared) return [];

  const knownNames = loadKnownNames();
  if (knownNames.length === 0) return [];

  const matches = findTyposquatMatches(declared.name, knownNames);
  if (matches.length === 0) return [];

  const relFile = path.relative(ctx.absTarget, ctx.skillMdPath).split(path.sep).join('/');

  return matches.map(
    (match): Finding => ({
      ruleId: 'sg10-typosquat-suspected',
      category: 'SG10',
      severity: 'MEDIUM',
      message: `SKILL.md declares name "${declared.name}", which closely resembles the well-known name "${match.knownName}" (edit distance ${match.distance}) — this may be an attempt to impersonate a popular skill or tool via typosquatting.`,
      file: relFile,
      line: declared.line,
    })
  );
}
