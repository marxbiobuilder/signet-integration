import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';

import { type JSONWebKeySet } from 'jose';

// A local JWKS endpoint for verifier tests that need keys to be FETCHED.
// Real HTTP rather than a mocked transport: createRemoteJWKSet's cache,
// cooldown and timeout all live inside jose, and mocking the transport
// leaves only our own fake corroborating itself. Plain http on 127.0.0.1:
// JwtVerifier fetches whatever it is handed.
export interface JwksServer {
  readonly calls: () => number;
  readonly close: () => Promise<void>;
  // Answer every later request with this status, simulating an issuer
  // outage or a broken endpoint.
  readonly fail: (status: number) => void;
  // Swap the served key set, simulating a rotation.
  readonly serve: (jwks: JSONWebKeySet) => void;
  // Answer 200 with this exact body, simulating an endpoint that is up but
  // not serving JSON.
  readonly serveRaw: (body: string) => void;
  readonly url: string;
}

export async function startJwksServer(
  jwks: JSONWebKeySet,
): Promise<JwksServer> {
  let body = JSON.stringify(jwks);
  let status = 200;
  let calls = 0;
  const server: Server = createServer((_req, res) => {
    calls += 1;
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    calls: () => calls,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
    fail: (next) => {
      status = next;
    },
    serve: (next) => {
      body = JSON.stringify(next);
      status = 200;
    },
    serveRaw: (next) => {
      body = next;
      status = 200;
    },
    url: `http://127.0.0.1:${port}/.well-known/jwks.json`,
  };
}
