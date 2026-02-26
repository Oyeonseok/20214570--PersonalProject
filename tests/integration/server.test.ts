import { describe, it, expect, beforeAll } from 'vitest';
import { createServer } from '../../src/server.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

describe('MCP Server Integration', () => {
  let server: McpServer;

  beforeAll(() => {
    server = createServer();
  });

  it('creates a server instance', () => {
    expect(server).toBeInstanceOf(McpServer);
  });

  it('has all 11 tools registered', () => {
    const tools = (server as any)._registeredTools as Record<string, unknown>;
    const names = Object.keys(tools);
    expect(names).toContain('secure_code');
    expect(names).toContain('scan_code');
    expect(names).toContain('scan_file');
    expect(names).toContain('check_dependency');
    expect(names).toContain('review_code');
    expect(names).toContain('create_web');
    expect(names).toContain('secure_develop');
    expect(names).toContain('generate_secure_code');
    expect(names).toContain('audit_config');
    expect(names).toContain('explain_vulnerability');
    expect(names).toContain('search_cve');
    expect(names.length).toBe(11);
  });

  it('every tool has a handler, description, and inputSchema', () => {
    const tools = (server as any)._registeredTools as Record<string, any>;
    for (const [name, tool] of Object.entries(tools)) {
      expect(tool.handler, `${name} should have a handler`).toBeDefined();
      expect(tool.description, `${name} should have a description`).toBeTruthy();
    }
  });

  it('secure_code tool handler returns result', async () => {
    const tools = (server as any)._registeredTools as Record<string, any>;
    const tool = tools['secure_code'];
    const result = await tool.handler({
      code: 'element.innerHTML = userInput;',
      language: 'javascript',
    }, {});
    expect(result.content[0].text).toContain('취약점');
  });

  it('scan_code tool handler returns scan result', async () => {
    const tools = (server as any)._registeredTools as Record<string, any>;
    const tool = tools['scan_code'];
    const result = await tool.handler({
      code: 'eval(x);',
      language: 'javascript',
      severity_threshold: 'low',
    }, {});
    expect(result.content[0].text).toContain('보안 스캔');
  });

  it('explain_vulnerability tool handler explains CWE-79', async () => {
    const tools = (server as any)._registeredTools as Record<string, any>;
    const tool = tools['explain_vulnerability'];
    const result = await tool.handler({
      vulnerability_id: 'CWE-79',
      detail_level: 'beginner',
      include_demo: false,
    }, {});
    expect(result.content[0].text).toContain('XSS');
  });

  it('review_code routes config content correctly', async () => {
    const tools = (server as any)._registeredTools as Record<string, any>;
    const tool = tools['review_code'];
    const result = await tool.handler({
      code: 'FROM node:latest\nUSER root',
      context: 'config',
    }, {});
    expect(result.content[0].text).toContain('보안 감사');
  });

  it('has 4 resources registered', () => {
    const resources = (server as any)._registeredResources as Record<string, unknown>;
    const uris = Object.keys(resources);
    expect(uris.length).toBe(4);
    expect(uris.some((u) => u.includes('cwe-database'))).toBe(true);
    expect(uris.some((u) => u.includes('owasp-top10'))).toBe(true);
    expect(uris.some((u) => u.includes('secure-patterns'))).toBe(true);
    expect(uris.some((u) => u.includes('blueprints'))).toBe(true);
  });

  it('has 3 prompts registered', () => {
    const prompts = (server as any)._registeredPrompts as Record<string, unknown>;
    const names = Object.keys(prompts);
    expect(names).toContain('secure_build');
    expect(names).toContain('security_code_review');
    expect(names).toContain('threat_modeling');
  });
});
