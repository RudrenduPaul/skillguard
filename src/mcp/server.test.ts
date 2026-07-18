import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from './server';

const EXAMPLES_DIR = path.resolve(__dirname, '..', '..', 'examples');

interface TextContent {
  type: 'text';
  text: string;
}

async function connectedClient(): Promise<Client> {
  const server = createServer();
  const client = new Client({ name: 'skillguard-test-client', version: '0.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

function firstText(content: unknown): string {
  const blocks = content as TextContent[];
  return blocks[0].text;
}

describe('mcp server: scan_skill tool (in-process, no stdio child process)', () => {
  it('advertises scan_skill with the documented input fields', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();

    const tool = tools.find((t) => t.name === 'scan_skill');
    expect(tool).toBeDefined();
    expect(tool!.description).toContain('third-party');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const schema = tool!.inputSchema as any;
    expect(Object.keys(schema.properties)).toEqual(
      expect.arrayContaining(['path', 'severityThreshold', 'timeoutMs'])
    );
    expect(schema.required).toEqual(['path']);
  });

  it('scanning examples/known-bad-skill returns findings and exit code 1', async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: { path: path.join(EXAMPLES_DIR, 'known-bad-skill') },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(firstText(result.content));
    expect(parsed.exitCode).toBe(1);
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.summary.HIGH).toBeGreaterThan(0);
  });

  it('scanning examples/clean-skill returns a clean result with exit code 0', async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: { path: path.join(EXAMPLES_DIR, 'clean-skill') },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(firstText(result.content));
    expect(parsed.exitCode).toBe(0);
    expect(parsed.findings).toEqual([]);
  });

  it('honors a severityThreshold override, same as the CLI --severity-threshold flag', async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: {
        path: path.join(EXAMPLES_DIR, 'known-bad-skill'),
        severityThreshold: 'LOW',
      },
    });

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(firstText(result.content));
    expect(parsed.severityThreshold).toBe('LOW');
    expect(parsed.exitCode).toBe(1);
  });

  it('rejects an invalid severityThreshold with a structured tool error instead of crashing', async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: {
        path: path.join(EXAMPLES_DIR, 'clean-skill'),
        severityThreshold: 'NOT_A_LEVEL',
      },
    });

    expect(result.isError).toBe(true);
    const text = firstText(result.content);
    expect(text).toContain('WHAT:');
    expect(text).toContain('WHY:');
    expect(text).toContain('FIX:');
  });

  it('rejects a non-positive timeoutMs with a structured tool error', async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: {
        path: path.join(EXAMPLES_DIR, 'clean-skill'),
        timeoutMs: -5,
      },
    });

    expect(result.isError).toBe(true);
    expect(firstText(result.content)).toContain('timeoutMs must be a positive number');
  });

  it('never honors a .skillguardignore or inline suppression from inside the scan target (no such options are exposed)', async () => {
    // SECURITY: the tool's input schema only accepts path/severityThreshold/timeoutMs
    // -- there is no way for a caller to pass ignoreFilePath or
    // allowInlineSuppression through this tool, so scanSkill() always runs
    // with both at their safest default. Verify this by confirming the
    // known-bad-skill fixture (which ships no .skillguardignore itself)
    // still reports all its findings through the MCP path, matching the
    // CLI/library behavior exercised in src/scan/index.e2e.test.ts.
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: { path: path.join(EXAMPLES_DIR, 'known-bad-skill') },
    });
    const parsed = JSON.parse(firstText(result.content));
    const categories = new Set(parsed.findings.map((f: { category: string }) => f.category));
    expect(categories.size).toBeGreaterThanOrEqual(3);
  });

  it('target-not-found path reports exit code 2 and isError true', async () => {
    const client = await connectedClient();
    const result = await client.callTool({
      name: 'scan_skill',
      arguments: { path: path.join(EXAMPLES_DIR, 'does-not-exist-fixture') },
    });

    expect(result.isError).toBe(true);
    const parsed = JSON.parse(firstText(result.content));
    expect(parsed.exitCode).toBe(2);
  });
});
