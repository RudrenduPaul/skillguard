import { z } from 'zod';

/**
 * The rule-pack plugin contract: a rule pack is a
 * directory with a pack.json manifest plus its .yml pattern-rule file (for
 * "pattern" packs) or a reference to a first-party structural module (for
 * "structural" packs — v0.1 only ships one, SG07's frontmatter/behavior diff).
 *
 * Every manifest is validated against this schema before its pack is allowed
 * to run. An invalid manifest causes that single pack to be skipped with a
 * warning — it never hard-fails the whole scan.
 */

const SEMVER_RE = /^\d+\.\d+\.\d+$/;

export const PackManifestSchema = z
  .object({
    name: z.string().min(1, 'name must be a non-empty string'),
    version: z.string().regex(SEMVER_RE, 'version must be semver, e.g. "0.1.0"'),
    category: z.enum(['SG01', 'SG02', 'SG03', 'SG04', 'SG05', 'SG06', 'SG07'], {
      errorMap: () => ({ message: 'category must be one of SG01..SG07' }),
    }),
    minCoreVersion: z.string().regex(SEMVER_RE, 'minCoreVersion must be semver, e.g. "0.1.0"'),
    description: z.string().min(1, 'description must be a non-empty string'),
    kind: z.enum(['pattern', 'structural']).default('pattern'),
    rulesFile: z.string().optional(),
  })
  .refine((manifest) => manifest.kind !== 'pattern' || !!manifest.rulesFile, {
    message: 'rulesFile is required when kind is "pattern"',
    path: ['rulesFile'],
  });

export type PackManifest = z.infer<typeof PackManifestSchema>;

export const RuleSeveritySchema = z.enum(['HIGH', 'MEDIUM', 'LOW']);

export const PatternRuleSchema = z.object({
  id: z.string().min(1),
  message: z.string().min(1),
  severity: RuleSeveritySchema,
  languages: z.array(z.enum(['javascript', 'typescript', 'python', 'shell'])).min(1),
  regex: z.string().min(1),
  flags: z.string().optional().default('gi'),
});

export const RulesFileSchema = z.object({
  rules: z.array(PatternRuleSchema).min(1),
});

export type PatternRule = z.infer<typeof PatternRuleSchema>;

/** Compares two semver strings (a >= b). No pre-release/build-metadata support — not needed for this contract. */
export function semverGte(a: string, b: string): boolean {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0);
  }
  return true;
}
