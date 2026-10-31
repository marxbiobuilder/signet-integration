import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  type CallToolResult,
  CallToolResultSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

export interface Upstream {
  readonly tools: readonly Tool[];
  call(
    name: string,
    args: Record<string, unknown> | undefined,
    signal: AbortSignal,
  ): Promise<CallToolResult>;
  close(): Promise<void>;
}

export async function connectUpstream(
  resource: string,
  token: string,
  signal: AbortSignal,
): Promise<Upstream> {
  const target = new URL(resource);
  const client = new Client({
    name: 'signet-device-adapter',
    version: '0.1.0',
  });
  const transport = new StreamableHTTPClientTransport(target, {
    fetch: async (url, init) => {
      // The SDK also performs metadata discovery after a 401. Never attach
      // credentials to that path, or forward them across a redirect.
      const destination = new URL(url);
      if (destination.href !== target.href)
        throw new Error('upstream_target_refused');
      const headers = new Headers(init?.headers);
      headers.set('Authorization', `Bearer ${token}`);
      return fetch(destination, {
        ...init,
        headers,
        redirect: 'error',
        signal: AbortSignal.any([
          signal,
          ...(init?.signal ? [init.signal] : []),
          AbortSignal.timeout(30000),
        ]),
      });
    },
  });
  try {
    await client.connect(transport, { signal, timeout: 15000 });
    const tools: Tool[] = [];
    const cursors = new Set<string>();
    let cursor: string | undefined;
    do {
      const page = await client.listTools(cursor ? { cursor } : undefined, {
        signal,
        timeout: 15000,
      });
      tools.push(...page.tools);
      cursor = page.nextCursor;
      if (tools.length > 1000 || (cursor && cursors.has(cursor)))
        throw new Error('upstream_tools_invalid');
      if (cursor) cursors.add(cursor);
    } while (cursor);
    if (new Set(tools.map((tool) => tool.name)).size !== tools.length)
      throw new Error('upstream_tools_invalid');
    return {
      call: async (name, args, callSignal) =>
        CallToolResultSchema.parse(
          await client.callTool(
            { arguments: args, name },
            CallToolResultSchema,
            {
              signal: callSignal,
              timeout: 60000,
            },
          ),
        ),
      close: () => client.close(),
      tools,
    };
  } catch {
    await client.close().catch(() => undefined);
    throw new Error('upstream_connection_failed');
  }
}
