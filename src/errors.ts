/**
 * Every error and warning surfaced by SkillGuard follows a fixed WHAT/WHY/FIX
 * three-line format (locked by the [redacted]), so a CI engineer trusting
 * SkillGuard as a blocking gate always knows what broke, why, and how to fix it.
 */
export function formatWhatWhyFix(what: string, why: string, fix: string): string {
  return `WHAT: ${what}\nWHY: ${why}\nFIX: ${fix}`;
}

export class SkillGuardError extends Error {
  constructor(what: string, why: string, fix: string) {
    super(formatWhatWhyFix(what, why, fix));
    this.name = 'SkillGuardError';
  }
}
