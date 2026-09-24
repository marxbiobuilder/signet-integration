import {
  exportJWK,
  generateKeyPair,
  type JSONWebKeySet,
  type JWTPayload,
  type KeyLike,
  SignJWT,
} from 'jose';

import { type JwksServer, startJwksServer } from './jwks-server';

// An issuer for tests: one ES256 key served over a local JWKS endpoint, and a
// signer that mints tokens in the SHAPE Signet issues -- `aud` as a
// single-element array, scopes in `scp` (Hydra's spelling), `client_id`
// present. A test that needs another shape passes the payload explicitly.
export interface TestIssuer {
  readonly close: () => Promise<void>;
  readonly jwks: JSONWebKeySet;
  readonly keys: JwksServer;
  readonly sign: (
    payload: JWTPayload,
    header?: { typ?: string },
  ) => Promise<string>;
  readonly signSignetToken: (input: {
    audience: string;
    clientId: string;
    issuer: string;
    scopes: readonly string[];
    subject: string;
  }) => Promise<string>;
}

export async function startTestIssuer(): Promise<TestIssuer> {
  const pair = await generateKeyPair('ES256');
  const signingKey: KeyLike = pair.privateKey;
  const jwks: JSONWebKeySet = {
    keys: [{ ...(await exportJWK(pair.publicKey)), alg: 'ES256', kid: 'k1' }],
  };
  const keys = await startJwksServer(jwks);
  const sign = (payload: JWTPayload, header: { typ?: string } = {}) =>
    new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256', kid: 'k1', ...header })
      .setExpirationTime('5m')
      .sign(signingKey);
  return {
    close: () => keys.close(),
    jwks,
    keys,
    sign,
    signSignetToken: ({ audience, clientId, issuer, scopes, subject }) =>
      sign({
        aud: [audience],
        client_id: clientId,
        iss: issuer,
        scp: [...scopes],
        sub: subject,
      }),
  };
}
