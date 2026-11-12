const byteLimit = 64 * 1024;

function parseRpc(
  chunks: Uint8Array[],
  contentType: string | null,
): Record<string, unknown> | undefined {
  const text = Buffer.concat(chunks).toString('utf8');
  const json = contentType?.includes('text/event-stream')
    ? text
        .split(/\r?\n/)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
        .join('\n')
    : text;
  try {
    const parsed: unknown = JSON.parse(json);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return;
  }
}

// Inspect a bounded request clone without consuming the transport's body.
export async function inspectRpc(
  message: Request,
): Promise<Record<string, unknown> | undefined> {
  const reader = message.body?.getReader();
  if (!reader) return;
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > byteLimit) {
        // Awaiting one tee branch's cancellation can wait for the other one.
        void reader.cancel().catch(() => undefined);
        return;
      }
      chunks.push(value);
    }
    return parseRpc(chunks, message.headers.get('content-type'));
  } catch {
    return;
  } finally {
    reader.releaseLock();
  }
}

// Observe only bytes the consumer requests. Forward every chunk immediately;
// EOF, source error and cancellation each produce exactly one terminal record.
export function observeRpc(
  response: Response,
  complete: (
    rpc: Record<string, unknown> | undefined,
    completed: boolean,
  ) => void,
): ReadableStream<Uint8Array> | null {
  const reader = response.body?.getReader();
  if (!reader) {
    complete(undefined, true);
    return null;
  }
  let chunks: Uint8Array[] = [];
  let size = 0;
  let finished = false;
  const finish = (valid: boolean) => {
    if (finished) return;
    finished = true;
    complete(
      valid && size <= byteLimit
        ? parseRpc(chunks, response.headers.get('content-type'))
        : undefined,
      valid,
    );
    chunks = [];
  };
  return new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          finish(true);
          reader.releaseLock();
          controller.close();
          return;
        }
        size += value.byteLength;
        if (size <= byteLimit) chunks.push(value);
        else chunks = [];
        controller.enqueue(value);
      } catch (error) {
        finish(false);
        reader.releaseLock();
        controller.error(error);
      }
    },
    async cancel(reason) {
      finish(false);
      try {
        await reader.cancel(reason);
      } finally {
        reader.releaseLock();
      }
    },
  });
}

export function rpcMethod(value: unknown): string {
  return typeof value === 'string' &&
    [
      'initialize',
      'ping',
      'tools/list',
      'tools/call',
      'notifications/initialized',
    ].includes(value)
    ? value
    : 'unknown';
}
