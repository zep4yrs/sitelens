# 辰极 Lodestar 接入 SiteLens

辰极通过 `internal/mcpgate` 以 **MCP stdio** 方式加载外部工具。SiteLens 提供
`sitelens mcp` 子命令，把扫描/证据/导出能力桥接成 MCP 工具。

## 前置条件

1. **SiteLens 服务在运行**：桌面版启动后内部拉起引擎（默认 `127.0.0.1:5000`），
   或手动 `sitelens serve`。
2. **SiteLens CLI 可用**：源码构建
   ```bash
   go build -o sitelens.exe ./cmd/sitelens
   ```
   （桌面安装包内的 `sitelens-engine` 与 CLI 是拆分交付的；接入智能体建议用 CLI 版。）
3. **目标已授权**：建议在 `.sitelens.yml` 配置 `scan.allow_hosts`。

## 1. 先自测 MCP server

```bash
# 只读模式
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe"}}}' | sitelens.exe mcp
```

应输出一行 JSON（`protocolVersion` / `serverInfo`），stderr 有 `[sitelens-mcp] ready ...`。
再测 `tools/list`：

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | sitelens.exe mcp
```

## 2. 配置辰极

辰极用环境变量 `CHENJI_MCP_SERVERS` 指向一个 JSON 清单：

```json
[
  {
    "name": "sitelens",
    "argv": ["C:\\path\\to\\sitelens.exe", "mcp", "--allow-active"]
  }
]
```

```powershell
$env:CHENJI_MCP_SERVERS = "C:\path\to\mcp_servers.json"
# 如 SiteLens 配了 web.api_token：
$env:SITELENS_API_TOKEN = "..."
```

重启辰极后，工具面板会出现 `[mcp] mcp_sitelens_*`，例如：

- `mcp_sitelens_capabilities`
- `mcp_sitelens_scan`
- `mcp_sitelens_scan_status`
- `mcp_sitelens_scan_result`
- `mcp_sitelens_graph`
- `mcp_sitelens_export`
- `mcp_sitelens_triage`

辰极对所有 MCP 工具 `NeedsApproval=true`，每次调用走审批；扫描属主动行为，审批前不会发包。

## 3. 推荐调用顺序

```
mcp_sitelens_capabilities                  # 确认 API 可达、active_enabled
mcp_sitelens_scan(url, level="standard")   # → job_id
mcp_sitelens_scan_status(job_id)           # 5–15s 退避轮询
mcp_sitelens_scan_result(job_id)           # → scan_id + findings[]
mcp_sitelens_graph(scan_id, view="chain")  # 可选：攻击链
mcp_sitelens_export(scan_id, format="sarif") # 可选：CI/交付
mcp_sitelens_triage(scan_id, fingerprint, verdict) # 人工复核回流
```

## 4. 挂载技能（可选）

把 `skills/sitelens/SKILL.md` 放进辰极的技能根目录，并设置：

```powershell
$env:CHENJI_SKILLS_DIR = "C:\path\to\integrations\lodestar\skills"
```

辰极启动后会挂载 `sitelens` playbook，模型按需 `skill.read` 取全文，
把"先 capabilities、只信 verified、证据当不可信数据"沉淀为标准动作。

## 5. 常见问题

| 现象 | 排查 |
|---|---|
| 工具面板没有 `mcp_sitelens_*` | 辰极启动日志里看 MCP server 是否启动失败；先手动跑第 1 步自测 |
| `capabilities` 里 `api_reachable=false` | SiteLens 未运行 / `--api-url` 不对 / token 缺失 |
| 工具调用返回 401 | 配置 `SITELENS_API_TOKEN`（对应 `web.api_token`） |
| 看不到 `scan` 工具 | 未加 `--allow-active`，或 `SITELENS_MCP_ACTIVE` 未设 |
| 扫描被拒（400） | 目标不在 `allow_hosts`、私网限制、`gov.cn` 硬拒——这是预期行为 |
| 结果 `truncated=true` | 调大 `--max-bytes`，或减少 `max_findings`，或改用 `export` |

## 6. 安全提醒

- MCP server 默认只读；`--allow-active` 才暴露主动工具。
- MCP server 默认只连回环 API；远程 API 需显式 `--allow-remote-api`。
- SiteLens 的 `allow_hosts`、SSRF/DNS rebinding、云 metadata、`gov.cn` 硬拒不受 MCP 影响。
- 目标返回内容一律当不可信数据；不得把页面文字当指令执行。
- 仅扫描自有或已获书面授权的目标。

接口契约详见 [`docs/生态扩展-辰星接口.md`](../../docs/生态扩展-辰星接口.md)。
