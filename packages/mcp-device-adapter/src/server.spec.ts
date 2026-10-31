import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolResultSchema,
  ToolListChangedNotificationSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { fixture, until } from './__spec__/fixture';
import { AuthSession } from './auth-session';
import { createAdapter } from './server';

describe('device MCP adapter', () => {
  let f: Awaited<ReturnType<typeof fixture>>;
  let session: AuthSession;

  beforeEach(async () => {
    f = await fixture();
  });
  afterEach(async () => {
    session?.disconnect();
    await f?.close();
  });

  it('performs device login and real HTTP MCP calls, preserves schemas/results, and redacts credentials', async () => {
    const token = await f.issue();
    const adapter = createAdapter(f.profile, { runtime: f.runtime });
    session = adapter.session;
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'bot', version: '1.0.0' });
    let changes = 0;
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      changes++;
    });
    await adapter.server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      expect((await client.listTools()).tools.map((tool) => tool.name)).toEqual(
        ['signet_auth_begin', 'signet_auth_status', 'signet_auth_disconnect'],
      );
      const begin = await client.callTool({ name: 'signet_auth_begin' });
      expect(JSON.stringify(begin)).toContain('ABCD-EFGH');
      expect(JSON.stringify(begin)).not.toContain(f.deviceCode);
      await until(() => session.status().state === 'ready');
      const tools = (await client.listTools()).tools;
      expect(
        tools.find((tool) => tool.name === 'upstream__lookup'),
      ).toMatchObject({
        annotations: { readOnlyHint: true },
        inputSchema: { properties: { query: { type: 'string' } } },
      });
      const result = CallToolResultSchema.parse(
        await client.callTool({
          arguments: { query: 'purchase' },
          name: 'upstream__lookup',
        }),
      );
      expect(result.structuredContent).toEqual({
        arguments: { query: 'purchase' },
        ok: true,
      });
      expect(JSON.stringify(result)).toContain('[REDACTED]');
      expect(JSON.stringify(result)).not.toContain(token);
      expect(JSON.stringify(result)).not.toContain(f.deviceCode);
      expect(changes).toBeGreaterThan(0);
      expect(
        f.requests
          .filter((request) => request.path === '/jwks')
          .every((request) => request.authorization === undefined),
      ).toBe(true);
      await client.callTool({ name: 'signet_auth_disconnect' });
      expect(session.status().state).toBe('idle');
      expect((await client.listTools()).tools).toHaveLength(3);
      expect(f.calls()).toBe(1);
    } finally {
      await client.close();
      await adapter.server.close();
    }
  });

  it.each([
    { aud: ['https://other-resource.example/api/mcp'] },
    { aud: ['SELF', 'https://other-resource.example/api/mcp'] },
    { iss: 'https://other-issuer.example' },
    { exp: 1 },
    { exp: undefined },
    { sub: '' },
    { client_id: 'other-client' },
    { scp: [] },
    { email: undefined },
  ])(
    'rejects unusable credentials before contacting the resource: %j',
    async (claims) => {
      const payload =
        Array.isArray(claims.aud) && claims.aud[0] === 'SELF'
          ? { ...claims, aud: [f.profile.resource, ...claims.aud.slice(1)] }
          : claims;
      await f.issue(payload);
      session = new AuthSession(f.profile, () => undefined, {
        runtime: f.runtime,
      });
      await session.begin();
      await until(() => session.status().state === 'error');
      expect(session.tools()).toEqual([]);
      expect(f.requests.some((request) => request.path === '/api/mcp')).toBe(
        false,
      );
    },
  );

  it('disconnect cancels pending polling and a later authorization cannot revive the old transaction', async () => {
    session = new AuthSession(f.profile, () => undefined, {
      runtime: f.runtime,
    });
    await session.begin();
    expect(session.status().state).toBe('pending');
    session.disconnect();
    await f.issue();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(session.status().state).toBe('idle');
    expect(f.requests.some((request) => request.path === '/api/mcp')).toBe(
      false,
    );
  });

  it('does not follow MCP redirects with a token', async () => {
    const token = await f.issue();
    f.redirectMcp();
    session = new AuthSession(f.profile, () => undefined, {
      runtime: f.runtime,
    });
    await session.begin();
    await until(() => session.status().state === 'error');
    expect(f.requests.some((request) => request.path === '/stolen')).toBe(
      false,
    );
    expect(JSON.stringify(session.status())).not.toContain(token);
  });

  it('never automatically replays failed tool calls and removes authorization on failure', async () => {
    const token = await f.issue();
    session = new AuthSession(f.profile, () => undefined, {
      runtime: f.runtime,
    });
    await session.begin();
    await until(() => session.status().state === 'ready');
    f.failTools();
    const result = await session.call(
      'upstream__lookup',
      {},
      new AbortController().signal,
    );
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).not.toContain(token);
    expect(JSON.stringify(result)).not.toContain(f.deviceCode);
    expect(f.calls()).toBe(1);
    expect(session.status().state).toBe('reauth_required');
    await session.call('upstream__lookup', {}, new AbortController().signal);
    expect(f.calls()).toBe(1);
  });

  it('forgets an expired token before any later tool call', async () => {
    let now = Date.now();
    await f.issue();
    session = new AuthSession(f.profile, () => undefined, {
      runtime: { ...f.runtime, now: () => now },
    });
    await session.begin();
    await until(() => session.status().state === 'ready');
    now += 400000;
    expect(
      (await session.call('upstream__lookup', {}, new AbortController().signal))
        .isError,
    ).toBe(true);
    expect(f.calls()).toBe(0);
    expect(session.status().state).toBe('reauth_required');
  });
});
