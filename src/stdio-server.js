import readline from 'node:readline';
import { createHcpJsonRpcDispatcher } from './jsonrpc.js';
import { createMcpClientShimDispatcher } from './mcp-adapter.js';

export function createJsonRpcLineHandler(dispatcher, writeLine) {
  return async function handleLine(line) {
    if (!line.trim()) return;
    const response = await dispatcher.handleJson(line);
    if (response !== null) {
      writeLine(JSON.stringify(response));
    }
    if (typeof dispatcher.drainNotifications === 'function') {
      for (const notification of dispatcher.drainNotifications()) {
        writeLine(JSON.stringify(notification));
      }
    }
  };
}

export function serveJsonRpcStdio({ runtime, dispatcher = null, input = process.stdin, output = process.stdout } = {}) {
  const activeDispatcher = dispatcher ?? createHcpJsonRpcDispatcher(runtime);
  const writeLine = (line) => output.write(`${line}\n`);
  const handleLine = createJsonRpcLineHandler(activeDispatcher, writeLine);
  const rl = readline.createInterface({ input, crlfDelay: Infinity });

  return new Promise((resolve, reject) => {
    let chain = Promise.resolve();

    rl.on('line', (line) => {
      chain = chain.then(() => handleLine(line)).catch((error) => {
        reject(error);
      });
    });

    rl.on('close', () => {
      chain.then(resolve, reject);
    });

    rl.on('error', reject);
  });
}

export function serveMcpStdio({ runtime, dispatcher = null, mcp = null, input = process.stdin, output = process.stdout } = {}) {
  const activeDispatcher = dispatcher ?? createMcpClientShimDispatcher(runtime, mcp ?? {});
  return serveJsonRpcStdio({ runtime, dispatcher: activeDispatcher, input, output });
}
