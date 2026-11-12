// Audit inspection never logs bodies. Bound the extra clone to avoid retaining
// arbitrary tool arguments or large document responses for observability.
export async function inspectRpc(
  message: Request | Response,
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
      if (size > 64 * 1024) {
        // Awaiting cancellation of one tee branch can wait for the other one.
        void reader.cancel().catch(() => undefined);
        return;
      }
      chunks.push(value);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    const json = message.headers
      .get('content-type')
      ?.includes('text/event-stream')
      ? text
          .split(/\r?\n/)
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trimStart())
          .join('\n')
      : text;
    const parsed: unknown = JSON.parse(json);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    // Malformed/closed/oversize messages are explicitly unobserved by callers;
    // they must never be reported as successful RPCs.
    return;
  } finally {
    reader.releaseLock();
  }
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
