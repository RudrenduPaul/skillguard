import type { Finding } from '../../types';
import type { StructuralAnalysisContext } from './index';
import {
  findSiblingSkillReferences,
  diffCrossSkillChaining,
} from '../../ast/cross-skill-chaining';
import { parseFrontmatter } from '../../ast/frontmatter-behavior-diff';

/**
 * SG09 structural analyzer — cross-skill privilege chaining (v1, sibling-
 * path heuristic). A thin adapter around src/ast/cross-skill-chaining.ts's
 * findSiblingSkillReferences()/diffCrossSkillChaining(), exposed through
 * the generic structural-analyzer `category`/`analyze` contract (see
 * src/scan/structural/index.ts). All of the actual detection/comparison
 * logic lives in cross-skill-chaining.ts; this file only wires it up.
 *
 * SCOPE LIMITATION: see cross-skill-chaining.ts's header comment. This is a
 * sibling-directory heuristic that works within skillguard's existing
 * single-skill-per-scan walker (src/walker.ts) — it is not a full
 * marketplace-wide, multi-skill dependency-graph analysis.
 */

export const category = 'SG09';

export function analyze(ctx: StructuralAnalysisContext): Finding[] {
  const references = findSiblingSkillReferences(ctx.files);
  if (references.length === 0) return [];

  // Frontmatter missing/unparseable for skill A itself is treated as "no
  // scope declared" (network/filesystem both false) rather than skipping
  // the check entirely -- a skill with no declared scope at all is, if
  // anything, more exposed to an undeclared privilege gain from a sibling,
  // not less, so silently skipping here would hide the riskier case.
  const ownDeclared = parseFrontmatter(ctx.skillMdContent) ?? {
    network: false,
    filesystemWrite: false,
  };

  return diffCrossSkillChaining(ownDeclared, ctx.absTarget, references);
}
