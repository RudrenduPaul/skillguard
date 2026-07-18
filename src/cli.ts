#!/usr/bin/env node
import { Command } from 'commander';
import { scanSkill } from './scan/index';
import { formatResult } from './output/formatters';
import type { OutputFormat, Severity } from './types';
import { formatWhatWhyFix } from './errors';
import { runMcpServer } from './mcp/server';

/*
 * Thin argument-parsing wrapper over src/scan/index.ts (see that file for the
 * full data-flow diagram). This file owns: flag parsing, the WHAT/WHY/FIX
 * error surface for bad CLI input, and the process exit-code contract.
 */

const SEVERITIES: Severity[] = ['HIGH', 'MEDIUM', 'LOW'];
const FORMATS: OutputFormat[] = ['human', 'json', 'sarif'];

function fail(what: string, why: string, fix: string): never {
  process.stderr.write(formatWhatWhyFix(what, why, fix) + '\n');
  process.exit(2);
}

function parseSeverity(value: string): Severity {
  const upper = value.toUpperCase();
  if (!SEVERITIES.includes(upper as Severity)) {
    fail(
      `Invalid --severity-threshold value "${value}".`,
      `--severity-threshold must be one of ${SEVERITIES.join(', ')}.`,
      `Pass one of: ${SEVERITIES.join(', ')}, e.g. --severity-threshold MEDIUM`
    );
  }
  return upper as Severity;
}

function parseFormat(value: string): OutputFormat {
  if (!FORMATS.includes(value as OutputFormat)) {
    fail(
      `Invalid --format value "${value}".`,
      `--format must be one of ${FORMATS.join(', ')}.`,
      `Pass one of: ${FORMATS.join(', ')}, e.g. --format sarif`
    );
  }
  return value as OutputFormat;
}

function parseTimeout(value: string): number {
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms <= 0) {
    fail(
      `Invalid --timeout value "${value}".`,
      '--timeout must be a positive number of milliseconds.',
      'Pass a positive number, e.g. --timeout 10000 for a 10-second per-file timeout.'
    );
  }
  return ms;
}

export async function runCli(argv: string[]): Promise<number> {
  const program = new Command();
  program
    .name('skillguard-cli')
    .description(
      'Security scanner for third-party AI agent-skill files: SKILL.md manifests, hooks, and bundled scripts.'
    )
    .version('0.2.0');

  let exitCode = 0;

  program
    .command('scan')
    .description('Scan a skill directory for known attack patterns')
    .argument('<path>', 'path to the skill directory to scan')
    .option('-f, --format <format>', 'output format: human, json, or sarif', 'human')
    .option(
      '-s, --severity-threshold <severity>',
      'minimum severity that fails the scan (HIGH, MEDIUM, or LOW)',
      'HIGH'
    )
    .option('-t, --timeout <ms>', 'per-file scan timeout in milliseconds', '10000')
    .option('--skillguardignore <path>', 'path to a .skillguardignore file (must be explicit -- never auto-loaded from inside the scan target, for security)')
    .option(
      '--allow-inline-suppression',
      'honor "# skillguard-ignore: SGxx" comments found inside the scanned files themselves. Off by default -- only enable this for a target you already trust, e.g. self-scanning your own skill before publishing.',
      false
    )
    .action(async (targetPath: string, opts) => {
      const format = parseFormat(opts.format);
      const severityThreshold = parseSeverity(opts.severityThreshold);
      const timeoutMs = parseTimeout(opts.timeout);

      if (format !== 'json') {
        // First-run friction fix: the pattern engine is
        // bundled, but scans of a new target can still take a moment on a
        // large directory — tell the user SkillGuard is working, not hung.
        process.stderr.write('Loading SkillGuard rule packs...\n');
      }

      const result = await scanSkill(targetPath, {
        severityThreshold,
        timeoutMs,
        ignoreFilePath: opts.skillguardignore,
        allowInlineSuppression: Boolean(opts.allowInlineSuppression),
      });

      process.stdout.write(formatResult(result, format) + '\n');
      exitCode = result.exitCode;
    });

  program
    .command('mcp')
    .description(
      'Start SkillGuard as an MCP (Model Context Protocol) server on stdio, exposing a ' +
        'scan_skill tool so another agent can call SkillGuard directly instead of shelling ' +
        'out to this CLI. See docs/integrations/mcp.md for client setup.'
    )
    .action(async () => {
      await runMcpServer();
    });

  await program.parseAsync(argv);
  return exitCode;
}

if (require.main === module) {
  // `mcp` starts a long-running stdio server (see src/mcp/server.ts):
  // runMcpServer()'s action only resolves once the client disconnects
  // (stdin closes), at which point Node exits naturally on its own -- no
  // explicit process.exit() call needed, or wanted: calling process.exit()
  // here as soon as runCli()'s promise resolves would work fine for the
  // one-shot `scan` subcommand, but would forcibly kill the `mcp`
  // subcommand's server the instant its action fires, before it ever serves
  // a single tool call.
  const isMcpMode = process.argv[2] === 'mcp';
  runCli(process.argv).then(
    (code) => {
      if (!isMcpMode) process.exit(code);
    },
    (err) => {
      process.stderr.write(
        formatWhatWhyFix(
          'skillguard-cli crashed unexpectedly.',
          err instanceof Error ? err.message : String(err),
          'Please open an issue at https://github.com/RudrenduPaul/skillguard/issues with the command you ran.'
        ) + '\n'
      );
      process.exit(2);
    }
  );
}
