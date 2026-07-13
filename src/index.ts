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
 */
export { scanSkill } from './scan/index';
export type {
  Finding,
  ScanOptions,
  ScanResult,
  ScanWarning,
  Severity,
  OutputFormat,
  RuleCategory,
} from './types';
