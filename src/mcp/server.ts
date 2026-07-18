#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { scanSkill } from '../scan/index';
import { formatJson } from '../output/formatters';
import type { Severity } from '../types';
import { formatWhatWhyFix } from '../errors';

/*
 * Agent-native MCP entry point, run via `skillguard-cli mcp` (see
 * src/cli.ts). This exposes the exact same `scanSkill()` used by the `scan`
 * subcommand as a single MCP tool, `scan_skill`, so another agent (Claude
 * Code, Cursor, an orchestrator, ...) can call SkillGuard directly as a tool
 * instead of shelling out to the CLI binary and parsing stdout.
 *
 * This file owns: MCP tool registration, input validation for the tool's
 * own arguments, and the stdio transport wiring. It does NOT reimplement any
 * scanning logic -- everything below `scanSkill()` is identical to the CLI
 * path, including every existing safety guarantee (see SECURITY comment in
 * src/scan/index.ts). In particular: the tool's input schema intentionally
 * does not expose `ignoreFilePath` or `allowInlineSuppression` at all, so a
 * calling agent has no way to make a scan honor a `.skillguardignore` file
 * or inline `# skillguard-ignore:` suppression comments -- scanSkill() is
 * always invoked with both left undefined, its safest default.
 *
 * Unlike the CLI (which is a one-shot process -- a bad flag calls
 * process.exit(2) and the process ends anyway), this is a long-running
 * server handling many tool calls over its lifetime. Invalid input for one
 * call must never crash the process out from under every other in-flight or
 * future call, so validation failures here return a normal CallToolResult
 * with isError: true instead of exiting.
 */

const SEVERITIES: Severity[] = ['HIGH', 'MEDIUM', 'LOW'];
const DEFAULT_TIMEOUT_MS = 10_000;
const SERVER_NAME = 'skillguard';
const SERVER_VERSION = '0.2.0';

interface ToolError {
  error: string;
}

function isToolError(value: unknown): value is ToolError {
  return typeof value === 'object' && value !== null && 'error' in value;
}

function parseSeverity(value: string | undefined): Severity | ToolError {
  if (value === undefined) return 'HIGH';
  const upper = value.toUpperCase();
  if (!SEVERITIES.includes(upper as Severity)) {
    return {
      error: formatWhatWhyFix(
        `Invalid severityThreshold value "${value}".`,
        `severityThreshold must be one of ${SEVERITIES.join(', ')}.`,
        `Pass one of: ${SEVERITIES.join(', ')}, e.g. severityThreshold: "MEDIUM"`
      ),
    };
  }
  return upper as Severity;
}

function parseTimeout(value: number | undefined): number | ToolError {
  if (value === undefined) return DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(value) || value <= 0) {
    return {
      error: formatWhatWhyFix(
        `Invalid timeoutMs value "${value}".`,
        'timeoutMs must be a positive number of milliseconds.',
        'Pass a positive number, e.g. timeoutMs: 10000 for a 10-second per-file timeout.'
      ),
    };
  }
  return value;
}

function toolError(message: string): CallToolResult {
  return {
    content: [{ type: 'text', text: message }],
    isError: true,
  };
}

/**
 * Builds the MCP server and registers the `scan_skill` tool. Exported
 * separately from `runMcpServer()` so tests can exercise tool calls
 * in-process (via the SDK's linked in-memory transport) without spawning a
 * child process.
 */
export function createServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.registerTool(
    'scan_skill',
    {
      title: 'Scan a third-party agent skill for known attack patterns',
      description:
        'Scans a third-party AI agent-skill directory (a SKILL.md manifest plus its ' +
        'hooks/scripts) for known attack patterns before it is installed or run: ' +
        'remote-code-execution hooks, declared-scope-vs-actual-behavior mismatches, ' +
        'file-scope escalation, supply-chain-risky install hooks, obfuscated payloads, ' +
        'and credential harvesting. Call this before installing or executing any ' +
        'agent skill that was not authored by you or your organization -- the same ' +
        'way you would not run an unreviewed shell script from a stranger. Returns a ' +
        'structured scan result (findings, severities, exit code) as JSON; a non-zero ' +
        'exit code means the skill tripped a finding at or above the configured ' +
        'severity threshold and should not be trusted without human review.',
      inputSchema: {
        path: z
          .string()
          .describe(
            'Filesystem path to the skill directory to scan (a directory containing a ' +
              'SKILL.md manifest plus any hooks/scripts).'
          ),
        severityThreshold: z
          .string()
          .optional()
          .describe(
            'Minimum severity that fails the scan: HIGH, MEDIUM, or LOW. Defaults to HIGH.'
          ),
        timeoutMs: z
          .number()
          .optional()
          .describe('Per-file scan timeout in milliseconds. Defaults to 10000.'),
      },
    },
    async ({ path: targetPath, severityThreshold, timeoutMs }) => {
      const severity = parseSeverity(severityThreshold);
      if (isToolError(severity)) return toolError(severity.error);

      const timeout = parseTimeout(timeoutMs);
      if (isToolError(timeout)) return toolError(timeout.error);

      // SECURITY: ignoreFilePath and allowInlineSuppression are deliberately
      // never passed here -- see the module-level comment above and the
      // SECURITY note in src/scan/index.ts. A calling agent cannot make this
      // tool honor a .skillguardignore file or inline suppression comments;
      // both stay at scanSkill()'s safest default (no path suppressions,
      // inline suppression off).
      const result = await scanSkill(targetPath, {
        severityThreshold: severity,
        timeoutMs: timeout,
      });

      return {
        content: [{ type: 'text', text: formatJson(result) }],
        isError: result.exitCode === 2,
      };
    }
  );

  return server;
}

export async function runMcpServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (require.main === module) {
  runMcpServer().catch((err) => {
    process.stderr.write(
      formatWhatWhyFix(
        'skillguard-cli mcp crashed unexpectedly.',
        err instanceof Error ? err.message : String(err),
        'Please open an issue at https://github.com/RudrenduPaul/skillguard/issues with the command you ran.'
      ) + '\n'
    );
    process.exit(2);
  });
}
