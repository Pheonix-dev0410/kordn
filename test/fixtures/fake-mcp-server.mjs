// Stand-in for `kordn --guardian <socket>` over stdio until the real server (#9) lands.
// Usage: fake-mcp-server.mjs <log file> [stateless|deny]
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const [log, variant = 'stateful'] = process.argv.slice(2);
const send = (msg) => process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...msg })}\n`);

createInterface({ input: process.stdin }).on('line', (line) => {
  appendFileSync(log, `${line}\n`);
  const msg = JSON.parse(line);
  if (msg.id === undefined) return;
  switch (msg.method) {
    case 'initialize':
      if (variant === 'stateless') return send({ id: msg.id, error: { code: -32601, message: 'Method not found' } });
      return send({ id: msg.id, result: { protocolVersion: msg.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'fake', version: '0' } } });
    case 'tools/list':
      return send({ id: msg.id, result: { tools: [{ name: 'af_get_balance', inputSchema: { type: 'object' } }, { name: 'af_list_transactions', inputSchema: { type: 'object' } }] } });
    case 'tools/call':
      if (variant === 'deny') return send({ id: msg.id, result: { isError: true, content: [{ type: 'text', text: 'SESSION_REVOKED' }] } });
      return send({ id: msg.id, result: { content: [{ type: 'text', text: '{"currency":"USD","balanceMinor":1}' }], structuredContent: { currency: 'USD', balanceMinor: 1 } } });
    default:
      return send({ id: msg.id, error: { code: -32601, message: 'Method not found' } });
  }
});
