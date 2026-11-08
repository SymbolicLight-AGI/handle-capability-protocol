# HCP Runtime

English · [简体中文](README.zh-CN.md)

**Paper** · [From Tool Connection to Execution Control: Benchmarking Security Invariants in MCP-Style Agent Runtimes](https://arxiv.org/abs/2606.29073)

HCP (Handle-Capability Protocol) is a Node.js reference runtime for tool-using agents. It lets an application grant a caller access to a specific tool and resource, check where a tool result may be sent, and trace the decision back to the task. It includes adapters for the Model Context Protocol (MCP).

For example, a caller can ask HCP to read customer notes and write a redacted copy to an approved file. The read returns a **handle**, a reference to the content held by the runtime. The caller can pass that handle to the write operation without copying the original notes into a model prompt.

## Try the data flow example

Use Node.js 20 or later. The example runs locally with built-in Node.js modules and requires no API key or model connection.

```sh
git clone https://github.com/SymbolicLight-AGI/handle-capability-protocol.git
cd handle-capability-protocol
node examples/data-pipe-demo.js
```

The script grants `user:alex` permission to read `notes.md` and write `out/redacted.md`. It passes the read handle to `dataPipe()` and explicitly requests a summary with email addresses and phone numbers redacted. HCP checks the caller's access to the handle and the target write permission before starting the write task. [Read the example](examples/data-pipe-demo.js).

Look for `[redacted:email]` and `[redacted:phone]` in the printed `written` field. The `audit_types` list includes `DATA_PIPE_SOURCE_CHECK` and `DATA_PIPE_POLICY_DECISION`. The final line is `data-pipe-demo-ok`. The script removes its temporary workspace when it finishes.

## Run the core tests

```sh
node --test test/runtime.test.js
```

The tests cover resource grants, denied operations, handle access and revocation, and audit records that link a transfer to its target task. [Core test cases](test/runtime.test.js).

## Use the CLI

From the repository root, list commands or search for capabilities available in the current workspace.

```sh
node src/cli.js --help
node src/cli.js demo .
```

To expose the runtime to an MCP client over standard input and output, launch `node src/cli.js mcp stdio .` from the repository root. The final argument selects the workspace directory. The CLI's `conformance` and `release` commands require the full development repository.

## License

HCP Runtime v0.3.0 is licensed under the [Apache License 2.0](LICENSE). See [NOTICE.md](NOTICE.md).
