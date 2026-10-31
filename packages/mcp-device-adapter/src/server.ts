import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import { AuthSession, toolError } from './auth-session';
import { type AdapterProfile } from './config';

const authTools: Tool[] = [
  [
    'signet_auth_begin',
    'Start device authorization. Give only the verification link and user code to the person who requested this connection. They sign in on their own device.',
  ],
  [
    'signet_auth_status',
    'Check authorization status. When ready, refresh the MCP tool list to discover the service tools.',
  ],
  [
    'signet_auth_disconnect',
    "Cancel pending authorization and forget this process's credentials. Already issued access tokens can remain valid until expiry.",
  ],
].map(([name, description]) => ({
  description,
  inputSchema: { additionalProperties: false, properties: {}, type: 'object' },
  name,
}));

export function createAdapter(
  profile: AdapterProfile,
  dependencies: ConstructorParameters<typeof AuthSession>[2] = {},
) {
  // Low-level Server preserves the upstream JSON schemas verbatim.
  const server = new Server(
    { name: 'signet-device-adapter', version: '0.1.0' },
    {
      capabilities: { tools: { listChanged: true } },
      instructions:
        'Use signet_auth_begin, show the link and code to the requester, then check signet_auth_status. When ready, refresh tools/list. Tokens are managed internally. Service tool results may contain private ERP data.',
    },
  );
  const session = new AuthSession(
    profile,
    () => {
      void server
        .notification({ method: 'notifications/tools/list_changed' })
        .catch(() => undefined);
    },
    dependencies,
  );
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [...authTools, ...session.tools()],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: args } = request.params;
    if (authTools.some((tool) => tool.name === name)) {
      if (args && Object.keys(args).length)
        return toolError('INVALID_ARGUMENTS');
      const value =
        name === 'signet_auth_begin'
          ? await session.begin()
          : name === 'signet_auth_disconnect'
            ? (session.disconnect(), session.status())
            : session.status();
      return {
        content: [
          { text: JSON.stringify(session.protect(value)), type: 'text' },
        ],
      };
    }
    return session.call(name, args, extra.signal);
  });
  server.onclose = () => session.disconnect();
  server.onerror = () => {
    /* Protocol diagnostics must never echo request data. */
  };
  return { server, session };
}
