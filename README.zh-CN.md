# HCP Runtime

[English](README.md) · 简体中文

HCP（Handle-Capability Protocol）是一个用 Node.js 实现的智能体工具调用参考运行时。应用可以指定谁有权用哪个工具操作哪份资源，检查工具返回的数据能发往哪里，并按任务查询授权或拒绝的原因。运行时提供了 MCP（Model Context Protocol，模型上下文协议）适配器。

例如，应用可以让 HCP 读取客户记录，把脱敏后的副本写到获准的文件。读取操作返回一个**句柄**，用来引用保存在运行时里的原文。调用方拿着句柄就能发起后续写入，整个过程无需把客户记录复制到模型提示词中。

## 运行数据流示例

使用 Node.js 20 或更高版本及 npm。示例只用 Node.js 内置模块，在本地即可运行，无需 API 密钥或连接模型。

```sh
git clone https://github.com/SymbolicLight-AGI/handle-capability-protocol.git
cd handle-capability-protocol
npm run demo:data-pipe
```

脚本授予 `user:alex` 读取 `notes.md` 和写入 `out/redacted.md` 的权限。它把读取时拿到的句柄传给 `dataPipe()`，并明确要求生成摘要、遮掉邮箱和电话号码。HCP 检查调用方能否使用这个句柄，以及是否有权写入目标文件，再启动写入任务。[查看示例源码](examples/data-pipe-demo.js)

运行后，输出的 `written` 字段里会出现 `[redacted:email]` 和 `[redacted:phone]`。`audit_types` 列出了这次操作的审计事件，包括源句柄检查 `DATA_PIPE_SOURCE_CHECK` 和传输策略判定 `DATA_PIPE_POLICY_DECISION`。最后一行是 `data-pipe-demo-ok`。脚本结束时会清理临时目录。

## 运行核心测试

```sh
npm test
```

测试覆盖资源授权、越权操作被拒绝、句柄的访问与撤销，以及如何通过审计记录找到一次传输对应的目标任务。[查看核心测试](test/runtime.test.js)

## 使用命令行

在仓库根目录运行以下命令，可以查看命令帮助，或搜索当前工作目录中可用的工具能力。

```sh
node src/cli.js --help
node src/cli.js demo .
```

要让 MCP 客户端通过标准输入输出连接运行时，可从仓库根目录启动 `node src/cli.js mcp stdio .`。最后一个参数指定工作目录。命令行中的 `conformance` 和 `release` 命令需要完整开发仓库。

## 论文与许可证

本仓库提供论文配套的参考运行时、一个可运行示例和核心测试。论文见 [From Tool Connection to Execution Control: Benchmarking Security Invariants in MCP-Style Agent Runtimes](https://arxiv.org/abs/2606.29073)。

HCP Runtime v0.3.0 采用 [Apache License 2.0](LICENSE)，相关声明见 [NOTICE.md](NOTICE.md)。
