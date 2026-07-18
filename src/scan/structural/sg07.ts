import type { Finding } from '../../types';
import type { StructuralAnalysisContext } from './index';
import {
  parseFrontmatter,
  inferActualBehavior,
  diffFrontmatterBehavior,
} from '../../ast/frontmatter-behavior-diff';

/**
 * SG07 structural analyzer — a thin adapter around
 * src/ast/frontmatter-behavior-diff.ts's existing parseFrontmatter /
 * inferActualBehavior / diffFrontmatterBehavior functions, exposed through
 * the generic structural-analyzer `category`/`analyze` contract (see
 * src/scan/structural/index.ts). All of the actual comparison logic still
 * lives in frontmatter-behavior-diff.ts; this file only wires it up.
 */

export const category = 'SG07';

export function analyze(ctx: StructuralAnalysisContext): Finding[] {
  const declared = parseFrontmatter(ctx.skillMdContent);
  if (!declared) return [];

  const actual = inferActualBehavior(ctx.files);
  return diffFrontmatterBehavior(declared, actual);
}
