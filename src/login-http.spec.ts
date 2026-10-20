import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';

import { fetchJson, LoginTransportError, transportFailure } from './login-http';

describe('transportFailure', () => {
  // Synthetic shapes: what is pinned is this function's rule, not undici's
  // current labels.
  it.each([
    [{ name: 'TimeoutError' }, 'TimeoutError'],
    [
      { cause: { code: 'ECONNREFUSED' }, name: 'TypeError' },
      'TypeError:ECONNREFUSED',
    ],
    [
      {
        cause: { code: 'UND_ERR_SOCKET', name: 'SocketError' },
        name: 'TypeError',
      },
      'TypeError:UND_ERR_SOCKET',
    ],
    [{ cause: { name: 'Error' }, name: 'TypeError' }, 'TypeError:Error'],
    [{ cause: { name: '' }, name: 'TypeError' }, 'TypeError'],
    [
      { cause: { code: 5, name: 'Error' }, name: 'TypeError' },
      'TypeError:Error',
    ],
    [{ name: '' }, 'unknown'],
    [{ name: 5 }, 'unknown'],
    [null, 'unknown'],
    [undefined, 'unknown'],
  ])('labels %j as %s', (error, label) => {
    expect(transportFailure(error)).toBe(label);
  });

  it('never carries the message, which can hold the URL', () => {
    const error = Object.assign(
      new TypeError('fetch failed: https://secret.example/'),
      {
        cause: new Error('connect to https://secret.example/'),
      },
    );
    expect(transportFailure(error)).toBe('TypeError:Error');
  });
});

describe('fetchJson', () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = createServer((request, response) => {
      if (request.url === '/redirect') {
        response.writeHead(307, { location: '/elsewhere' });
        response.end();
      } else if (request.url === '/reset') {
        request.socket.destroy();
      } else if (request.url === '/stall') {
        response.writeHead(200);
        response.write('{');
      } else {
        response.writeHead(200);
        response.end('{"ok":true}');
      }
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve),
    );
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const transportDetail = async (path: string, timeoutMs = 2_000) => {
    const error: unknown = await fetchJson(
      `${base}${path}`,
      {},
      timeoutMs,
    ).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(LoginTransportError);
    return (error as LoginTransportError).detail;
  };

  it('parses a JSON body', async () => {
    expect(await fetchJson(`${base}/`, {}, 2_000)).toEqual({
      body: { ok: true },
      json: true,
      ok: true,
      status: 200,
    });
  });

  it.each([
    ['a refused redirect', '/redirect'],
    ['a reset connection', '/reset'],
  ])(
    'reports %s as a transport failure with a cause label',
    async (_, path) => {
      expect(await transportDetail(path)).toMatch(/^TypeError:\S+$/);
    },
  );

  it('reports a body that stalls as a timeout', async () => {
    expect(await transportDetail('/stall', 200)).toBe('TimeoutError');
  });
});
