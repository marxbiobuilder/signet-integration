import assert from 'node:assert/strict';
import { test } from 'node:test';
import { observeRpc } from '../dist/rpc-audit.js';

test(
  'SSE audit forwards progress before EOF and observes cancellation',
  { timeout: 1000 },
  async () => {
    let source;
    const events = [];
    const stream = new ReadableStream({
      start(controller) {
        source = controller;
      },
    });
    const response = new Response(stream, {
      headers: { 'content-type': 'text/event-stream' },
    });
    const reader = observeRpc(response, (rpc) => events.push(rpc)).getReader();
    source.enqueue(new TextEncoder().encode(': progress\n\n'));
    // The source stays open: first bytes must arrive without waiting for EOF.
    const first = await reader.read();
    assert.equal(new TextDecoder().decode(first.value), ': progress\n\n');
    assert.equal(events.length, 0);
    source.enqueue(
      new TextEncoder().encode(
        'data: {"jsonrpc":"2.0","id":1,"result":{}}\n\n',
      ),
    );
    const second = await reader.read();
    assert.ok(new TextDecoder().decode(second.value).startsWith('data:'));
    source.close();
    assert.equal((await reader.read()).done, true);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].result, {});
    const cancelled = [];
    let reason;
    const open = new Response(
      new ReadableStream({
        cancel(value) {
          reason = value;
        },
      }),
    );
    const cancelledReader = observeRpc(open, (rpc) =>
      cancelled.push(rpc),
    ).getReader();
    await cancelledReader.cancel('consumer-stopped');
    assert.equal(reason, 'consumer-stopped');
    assert.deepEqual(cancelled, [undefined]);
  },
);

test('oversize replies forward unchanged and finish as unobserved', async () => {
  const body = JSON.stringify({ result: { text: 'x'.repeat(70000) } });
  const events = [];
  const forwarded = observeRpc(new Response(body), (rpc) => events.push(rpc));
  assert.equal(await new Response(forwarded).text(), body);
  assert.deepEqual(events, [undefined]);
});

test('source failure propagates to the consumer and records interrupted audit', async () => {
  let controller;
  const failure = new Error('fixture-stream-failure');
  const events = [];
  const response = new Response(
    new ReadableStream({
      start(source) {
        controller = source;
      },
    }),
  );
  const reader = observeRpc(response, (rpc, completed) =>
    events.push({ rpc, completed }),
  ).getReader();
  controller.error(failure);
  await assert.rejects(reader.read(), (error) => error === failure);
  assert.deepEqual(events, [{ rpc: undefined, completed: false }]);
});
