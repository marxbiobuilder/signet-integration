import { createServer } from 'node:http';
import { type AddressInfo } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

import { Server as McpServer } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { exportJWK, generateKeyPair, type JWTPayload, SignJWT } from 'jose';

import { type DeviceRuntime } from '../../../../src/core/device-flow';
import { fetchJson } from '../../../../src/core/login-http';
import { type AdapterProfile } from '../config';

export async function fixture() {
  const pair = await generateKeyPair('ES256');
  const jwks = {
    keys: [
      { ...(await exportJWK(pair.publicKey)), alg: 'ES256', kid: 'test-key' },
    ],
  };
  const requests: { path: string; authorization?: string; body?: unknown }[] =
    [];
  const failures: unknown[] = [];
  let base = '';
  let token: string | undefined;
  let callCount = 0;
  let toolFailure = false;
  let redirect = false;
  const deviceCode = 'private-device-code';
  const servers = new Set<McpServer>();
  const http = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of req)
        chunks.push(Buffer.from(chunk as Uint8Array));
      const raw = Buffer.concat(chunks).toString('utf8');
      requests.push({
        authorization: req.headers.authorization,
        body: raw,
        path: req.url ?? '',
      });
      const json = (body: unknown, status = 200) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (req.url === '/.well-known/openid-configuration') {
        json({
          device_authorization_endpoint: `${base}/device`,
          issuer: base,
          jwks_uri: `${base}/jwks`,
          token_endpoint: `${base}/token`,
        });
      } else if (req.url === '/.well-known/oauth-protected-resource/api/mcp') {
        json({ authorization_servers: [base], resource: `${base}/api/mcp` });
      } else if (req.url === '/jwks') {
        json(jwks);
      } else if (req.url === '/device') {
        json({
          device_code: deviceCode,
          expires_in: 600,
          interval: 1,
          user_code: 'ABCD-EFGH',
          verification_uri: `${base}/verify`,
        });
      } else if (req.url === '/token') {
        const params = new URLSearchParams(raw);
        if (params.get('device_code') !== deviceCode)
          throw new Error('wrong_device_code');
        json(
          token
            ? { access_token: token, expires_in: 300, token_type: 'Bearer' }
            : { error: 'authorization_pending' },
          token ? 200 : 400,
        );
      } else if (req.url === '/api/mcp') {
        if (redirect) {
          res.writeHead(307, { location: `${base}/stolen` });
          res.end();
          return;
        }
        if (!token || req.headers.authorization !== `Bearer ${token}`) {
          json({ error: 'unauthorized' }, 401);
          return;
        }
        if (req.method !== 'POST') {
          res.writeHead(405).end();
          return;
        }
        const server = new McpServer(
          { name: 'test-resource', version: '1.0.0' },
          { capabilities: { tools: {} } },
        );
        servers.add(server);
        server.setRequestHandler(ListToolsRequestSchema, () => ({
          tools: [
            {
              annotations: { readOnlyHint: true },
              inputSchema: {
                properties: { query: { type: 'string' } },
                type: 'object',
              },
              name: 'lookup',
            },
          ],
        }));
        server.setRequestHandler(CallToolRequestSchema, (request) => {
          callCount++;
          if (toolFailure)
            throw new Error(`private diagnostic ${token} ${deviceCode}`);
          return {
            content: [{ text: `result ${token} ${deviceCode}`, type: 'text' }],
            structuredContent: {
              arguments: request.params.arguments,
              ok: true,
            },
          };
        });
        const transport = new StreamableHTTPServerTransport({
          enableJsonResponse: true,
          sessionIdGenerator: undefined,
        });
        await server.connect(transport);
        await transport.handleRequest(
          req,
          res,
          raw ? (JSON.parse(raw) as unknown) : undefined,
        );
      } else {
        json({ error: 'not_found' }, 404);
      }
    })().catch((error: unknown) => {
      failures.push(error);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    http.once('error', reject);
    http.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  const profile: AdapterProfile = {
    allowLoopbackHttp: true,
    clientId: 'test-client',
    environment: 'staging',
    issuer: base,
    resource: `${base}/api/mcp`,
    scope: 'openid queries:read',
    service: 'lander',
  };
  const runtime: DeviceRuntime = {
    http: fetchJson,
    now: Date.now,
    wait: async (_ms, signal) => {
      await delay(2, undefined, { signal });
    },
  };
  return {
    base,
    calls: () => callCount,
    close: async () => {
      await Promise.all([...servers].map((server) => server.close()));
      http.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        http.close((error) => (error ? reject(error) : resolve())),
      );
      expect(failures).toEqual([]);
    },
    deviceCode,
    failTools: () => {
      toolFailure = true;
    },
    issue: async (claims: JWTPayload = {}) => {
      token = await new SignJWT({
        aud: [profile.resource],
        client_id: profile.clientId,
        email: 'person@example.test',
        exp: Math.floor(Date.now() / 1000) + 300,
        iss: base,
        scp: ['queries:read'],
        sub: 'person-1',
        ...claims,
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-key' })
        .sign(pair.privateKey);
      return token;
    },
    profile,
    redirectMcp: () => {
      redirect = true;
    },
    requests,
    runtime,
  };
}

export async function until(check: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (check()) return;
    await delay(5);
  }
  throw new Error('condition_not_reached');
}
