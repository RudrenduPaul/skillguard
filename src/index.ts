/**
 * Programmatic / agent-native entry point.
 *
 *   import { scanSkill } from 'skillguard-cli';
 *   const result = await scanSkill('./my-skill');
 *
 * Returns the same structured ScanResult the CLI formats for human/json/sarif
 * output — an agent framework can call this in-process instead of shelling
 * out to the CLI binary. Same core scan logic as `skillguard-cli scan`;
 * src/cli.ts is a thin argument-parsing wrapper over this function.
 *
 * Additive alongside scanSkill(): scanSkillSet() scans a directory whose
 * immediate children are each a skill directory (a marketplace bundle, a
 * project's .claude/skills/ folder, etc.) and layers a skill-set-level
 * structural check (SG09 -- cross-skill privilege chaining) on top of each
 * skill's own scanSkill()-equivalent result.
 *
 *   import { scanSkillSet } from 'skillguard-cli';
 *   const setResult = await scanSkillSet('./my-skills-dir');
 */
export { scanSkill } from './scan/index';
export { scanSkillSet, discoverSkillDirs, computeCrossSkillFindings } from './scan/skill-set';
export type {
  Finding,
  ScanOptions,
  ScanResult,
  ScanWarning,
  Severity,
  OutputFormat,
  RuleCategory,
  SkillEntry,
  SkillSetScanResult,
} from './types';
