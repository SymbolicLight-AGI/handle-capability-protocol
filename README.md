# HCP Runtime

HCP Runtime is the Node.js reference implementation of the Handle-Capability Protocol. It provides capability discovery, principal and resource grants, task execution, managed data handles, audit events, and MCP adapters.

## Run locally

Use Node.js 20 or later. From this directory, list the available commands and run a local capability search.

```sh
node src/cli.js --help
node src/cli.js demo .
```

To start the MCP interface over standard input and output, run `node src/cli.js mcp stdio .` from the workspace you want to use, with the path to `cli.js` adjusted accordingly. The CLI's `conformance` and `release` commands require the full development repository.

## Run the data flow example

From this directory, run the example with Node.js and npm. It uses only built-in Node.js modules and creates its own temporary workspace.

```sh
npm run demo:data-pipe
```

The example reads a sample file through a managed handle, redacts the email address and phone number, then writes the result to an authorized destination. It prints the output and audit event types, followed by `data-pipe-demo-ok`.

## Run the core tests

```sh
npm test
```

The tests exercise grants, handle access and revocation, data transfers, and audit records for allowed and denied operations.

## Source and license

Runtime source from commit `419c858`, package version `0.3.0`. See `LICENSE` and `NOTICE.md`.
