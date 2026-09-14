# SiteLens Graph JSONL Schema 参考（`sitelens.graph/v1`）

> **这份文档是 4.0 → 5.0 的数据接口契约。** 4.0 侧保证其内容与实现一致
> （`internal/model`，字段清单由代码导出核对）；5.0 ML 侧按本文读取。
> 建立于 2026-09-14（P9）。变更规则见文末「兼容性承诺」。

## 1. 这个接口是什么

4.0 每次开启「事实图」（扫描 payload `graph: true`，或 CLI `scan -graph`）会产出一份
**结构化安全事实图**，落盘为 **JSON Lines（JSONL）**：

```
data/state/graph/<scan_id>/
  ├── graph.jsonl     ← 本文件描述的行式数据（首行 header + 每实体一行）
  └── manifest.json   ← 元信息（schema/scan_id/counts/时间戳；便于不解析 JSONL 即知规模）
```

获取途径：
- **文件**：`data/state/graph/<id>/graph.jsonl`（本地直接读）
- **HTTP**：`GET /api/graph/{id}/jsonl`（`Content-Type: application/x-ndjson`）

5.0 只需**流式逐行读取**，不依赖 4.0 的任何内部实现、不 import Go 包、不需要 4.0 常驻。
**接口与语言无关**：JSONL 是普通 JSON，5.0 用 Python 读即可（§7.3 有等价实现示意）。

## 2. 文件结构

第 1 行固定为 **header**，其后每行一个实体记录。

```jsonc
// 第 1 行：header（非实体）
{"schema":"sitelens.graph/v1","kind":"header","version":"sitelens.graph/v1",
 "scan_id":"1","generated_at":"2026-09-14 22:47:41","entities":78}

// 其后每行：
{"schema":"sitelens.graph/v1","kind":"<实体类型>","entity":{ ...实体的字段... }}
```

`kind` 决定 `entity` 的具体结构（见 §4）。行序为 **(实体类型规范顺序, id 升序)**，
同一张图多次序列化字节一致（可用于做确定性校验）。

## 3. 稳定 ID

所有实体都有 `id`，格式 `<prefix>_<12位小写十六进制>`，由**内容确定性哈希**生成
（非自增、非随机）。**同一事实重复扫描得到相同 ID**——这是 5.0 能跨扫描聚合、
做时间切分与去重的基础。

| 前缀 | 实体 | 示例 |
|---|---|---|
| `ep` | entry_point | `ep_b452aec48469` |
| `vn` | vuln_node | `vn_293f226f8073` |
| `ev` | evidence | `ev_a4f89b550915` |
| `lnk` | evidence_link | `lnk_715c1b8623fe` |
| `df` | dataflow | `df_08f2d80acdb4` |
| `cwe` | cwe_rel | `cwe_aa013d781d83` |
| `cn` | chain_node | `cn_a82ddc37ce2a` |
| `ce` | chain_edge | `ce_d979dfdeef65` |
| `pc` | priv_change | `pc_...` |
| `im` | impact | `im_cccc55556666` |

> 5.0 侧**不要**自行构造/解析 ID 语义；把它当作不透明主键使用。

## 4. 实体字段清单（权威，与 `internal/model/entities.go` 一致）

枚举取值见 §5。标注 `?` 的字段可能缺失（Go `omitempty`）。

### 4.1 `entry_point` — 入口点
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | 稳定 ID（`ep_`） |
| `origin` | string | `blackbox` / `whitebox` |
| `kind` | string | `url` / `param` / `form` / `js_endpoint` / `route` / `function` |
| `url`? | string | 完整 URL |
| `method`? | string | HTTP 方法 |
| `param`? | string | 参数名（kind=param 时） |
| `params`? | []string | 表单字段名等 |
| `file`?, `func`?, `line`? | string/string/int | 白盒定位 |
| `evidence_ids` | []string | 证据引用（可为空；入口点是攻击面事实） |

### 4.2 `vuln_node` — 漏洞/风险节点（黑盒与白盒统一）
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `vn_` |
| `origin` | string | `blackbox` / `whitebox` |
| `check_id`? | string | 黑盒 check id（如 `xss-reflect`；情报为 `intel:<src>:<CVE>`） |
| `rule_id`? | string | 白盒规则 id（如 `PY-SQLFMT`、`AST-sql`） |
| `title`?, `severity`? | string | 标题 / 严重度（`critical`/`high`/`medium`/`low`） |
| `cve`? | string | 关联 CVE |
| `cwes`? | []string | 弱类型编号（如 `["CWE-89"]`） |
| `url`?, `param`? | string | 黑盒定位 |
| `file`?, `func`?, `line`? | string/string/int | 白盒定位 |
| `observation` | string | **四态**，见 §5.2（关键：区分「未执行」与「执行未命中」） |
| `verdict`? | string | 原始词表（`proven`/`observed`/`detected`/`possible`…，保留不丢信息） |
| `confidence` | string | 见 §5.3 |
| `entry_id`? | string | 指向 entry_point（**真实因果**：该发现落在哪个入口上） |
| `evidence_ids` | []string | 证据引用（`observation=positive` 时**必非空**） |

### 4.3 `evidence` — 原始证据（信任根）
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `ev_`，按内容寻址（同内容→同 ID，天然去重） |
| `kind` | string | `request`/`response`/`snippet`/`signals`/`payload`/`replay`/`source`/`sink`/`fingerprint`/`impact` |
| `origin` | string | `blackbox` / `whitebox` |
| `source`? | string | 产出方（`dast`/`checks`/`nuclei`/`passive`/`exploit`/`audit`/`modules`/`loginbrute`） |
| `scan_id`?, `url`?, `file`?, `line`? | | 定位 |
| `body`? | string | 证据正文（应答摘要 / 代码片段等） |
| `digest`? | string | 正文内容摘要（比对用） |
| `captured_at`? | string | 采集时间 |
| `truncated`? | bool | 正文是否被截断 |

### 4.4 `evidence_link` — 黑白盒关联边
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `lnk_` |
| `blackbox_vuln_id` | string | 黑盒节点 |
| `whitebox_dataflow_id`? | string | 白盒数据流 |
| `whitebox_vuln_id`? | string | 白盒节点 |
| `basis` | string | 关联依据：`url` / `param` / `tech` / `manual` |
| `confidence` | string | 自动产出最高 `probable`（**不给 `confirmed`**） |
| `evidence_ids` | []string | 两端证据合集 |

### 4.5 `dataflow` — 白盒数据流（source → sink）
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `df_` |
| `origin` | string | 固定 `whitebox` |
| `lang`? | string | `python`/`javascript`/`php`/`java`/`go` |
| `file`, `func`?, `param`? | string | 定位 |
| `source`?, `sink`? | object | `{kind,file,func,line,expr}` |
| `steps`? | []object | `{ordinal,kind,file,func,line,expr}` 传播轨迹 |
| `vuln_id`? | string | 关联白盒 vuln_node |
| `confidence` | string | 见 §5.3 |
| `evidence_ids` | []string | **必非空**（白盒数据流必须可追溯） |

### 4.6 `cwe_rel` — CWE 关联
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `cwe_` |
| `subject_kind` | string | `vuln_node`（当前） |
| `subject_id` | string | 关联主体 ID |
| `cwe_id` | string | 如 `CWE-89` |
| `source` | string | `mapping`（本地表）/ `nvd`（NVD weaknesses）/ `manual` |
| `confidence` | string | 自动为 `probable` |
| `evidence_ids` | []string | 证据引用 |

### 4.7 `chain_node` — 攻击链节点
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `cn_` |
| `kind` | string | `recon`/`entry`/`exploit`/`impact`/`priv` |
| `ref_id` | string | 指向的真实实体 ID（可为 vuln_node/entry_point/impact/priv_change） |
| `label`? | string | 可读标签 |
| `evidence_ids` | []string | 证据引用 |

### 4.8 `chain_edge` — 攻击链边（**证据驱动**）
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `ce_` |
| `from`, `to` | string | chain_node ID |
| `kind` | string | `sequence`（入口→发现的真实因果）/ `exploit_impact` / `evidence_link` / `priv_change` |
| `derived_from` | []string | **必非空**：支撑该边的 evidence ID 列表（红线：无证据不成边） |
| `confidence` | string | 自动为 `probable` |

### 4.9 `priv_change` — 权限变化
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `pc_` |
| `from`, `to` | string | 如 `anonymous` → `authenticated` / `restricted-resource` / `impact-reached` / `suspected-admin` / `unknown` |
| `mechanism` | string | `bypass-403` / `credential` / `exploit-proven` |
| `finding_id`? | string | 关联发现 |
| `evidence_ids` | []string | 证据引用 |
| `confidence` | string | 见 §5.3 |

### 4.10 `impact` — 影响
| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `im_` |
| `kind` | string | `disclosure`/`modification`/`dos`/`execution`/`redirect`/`ssrf`/`unknown` |
| `description`? | string | 补充说明 |
| `verdict`? | string | `proven`/`observed` |
| `priors`? | []string | **先验标注**（`kev`、`cvss:10.0`）——**仅解释，不参与建链** |
| `vuln_id`? | string | 关联 vuln_node |
| `evidence_ids` | []string | 证据引用 |
| `confidence` | string | 见 §5.3 |

## 5. 枚举取值

### 5.1 `origin`
`blackbox`（远程扫描）| `whitebox`（本地源码审计）

### 5.2 `observation`（**四态语义，必须区分**）
| 值 | 含义 |
|---|---|
| `positive` | 已执行且命中（**必有证据**） |
| `negative` | 已执行且未命中 |
| `not_executed` | **从未执行**（能力未开启/被取消/条件不满足） |
| `unknown` | 有该条目但当前无法判定 |

> ⚠️ 5.0 侧造负样本时，**只有 `negative` 可作负例**；`not_executed` / `unknown`
> 不得当负样本（这与 5.0 计划的「负样本纪律」一致）。

### 5.3 `confidence`
`confirmed` | `probable` | `possible` | `unresolved`
> 硬规则：**无证据不得 `confirmed`**（4.0 侧构造与校验双重把关；
> `evidence_link` / `cwe_rel` / `chain_edge` 的自动产出一律 `probable`）。

### 5.4 `chain_edge.kind`
`sequence` | `exploit_impact` | `evidence_link` | `priv_change`

### 5.5 `evidence_link.basis`
`url` | `param` | `tech` | `manual`

## 6. 5.0 投影对齐（对应 5.0 计划 Phase 11 / `ml/interfaces/v40.py`）

5.0 计划要求投影 **9 类** 4.0 实体；本 schema 全部覆盖（`evidence` 作为信任根另计）：

| 5.0 期望类 | schema `kind` | 备注 |
|---|---|---|
| 漏洞节点 | `vuln_node` | 含 `observation` 四态与 `confidence` |
| 链节点 | `chain_node` | |
| 链边 | `chain_edge` | `derived_from` 非空 = 证据可追溯 |
| 入口点 | `entry_point` | |
| CWE 关系 | `cwe_rel` | 来源 `mapping`（本地表）/ `nvd`（NVD weaknesses） |
| DataFlow | `dataflow` | source/sink/steps |
| 权限变化 | `priv_change` | 三种 mechanism |
| Impact | `impact` | `priors` 仅供解释 |
| 证据关联 | `evidence_link` | 黑白盒桥 |
| （信任根） | `evidence` | 5.0 侧按需读取，用于追溯 |

> **对齐状态（2026-09-14）**：5.0 计划中标注「（等待 4.0）」的项
> （攻击链 Node/Edge/Path 特征、CWE 关系特征、入口点特征、权限变化标签、
> 黑白盒证据关联特征）**数据侧已就绪**——4.0 P1-P8 已实现并在本 schema 中暴露。
> 5.0 可在其分支上按 Phase 11 落地 `ml/interfaces/v40.py`。
> 注意：5.0 Phase 11 只定义**投影 schema**，不在 4.0 分支写 Python 代码
> （4.0 分支不含 `ml/`）。

## 7. 读取示例

**本接口与语言无关**：graph JSONL 是普通 JSON，任何语言都能读。4.0 分支自带的
参考读端与验收工具是 **Go** 实现（保持 4.0 全仓 Go），5.0 侧可用 Python 自行实现。

### 7.1 4.0 自带读端（Go，只读工具）

```
sitelens graph-read <file.graph.jsonl>              # 摘要（计数/观测态/CWE/链边）
sitelens graph-read <file.graph.jsonl> --self-test  # 契约自检（恒不变式），退出码表达
```

退出码：`0`=通过 / `1`=契约违规 / `2`=读取失败。实现见 `internal/model/inspect.go`
（`InspectGraph` / `Inspect`），CLI 见 `cmd/sitelens/graphread.go`。

### 7.2 读取契约（任何语言照此实现）

1. 逐行读取；跳过空行。
2. 每行 `json.loads` / 等价解析；校验 `schema` 以 `sitelens.graph/v1` 开头
   （**不匹配必须报错**，不得继续）。
3. 首行必须是 `kind == "header"`（否则报错）；由它取 `scan_id` / `generated_at`。
4. 其余行按 `kind` 分派，取 `entity`。**未知 `kind` 跳过**（前向兼容）。
5. **未知字段忽略**（不要因多了字段而报错）。
6. 组装 `kind -> []entity`，即可开始消费。

### 7.3 Python 侧等价实现（示意，约 15 行）

```python
import json

def read_graph(path):
    ents, header = {}, None
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if not str(rec.get("schema", "")).startswith("sitelens.graph/v1"):
                raise ValueError(f"schema 不兼容：第 {i} 行")
            if rec["kind"] == "header":
                header = rec
                continue
            ents.setdefault(rec["kind"], []).append(rec.get("entity") or {})
    return header, ents

header, ents = read_graph("data/state/graph/1/graph.jsonl")
for vn in ents.get("vuln_node", []):
    if vn["observation"] == "positive":      # 只取真实命中
        print(vn["id"], vn.get("check_id") or vn.get("rule_id"),
              vn.get("cwes", []), len(vn.get("evidence_ids", [])))
```

> 上面 Python 片段是**文档示意**，不在 4.0 分支落代码（4.0 侧读端为 Go；
> 5.0 侧按 5.0 计划自行落地，可直接照此写 `ml/interfaces/v40.py`）。

## 8. 兼容性承诺

**前向兼容（4.0 加字段，5.0 旧读端不崩）**
- 新增**可选**字段：不升版本；读端未知字段必须忽略（Go `encoding/json` 与
  Python `json.loads` 天然容忍）。
- 新增**实体 kind**：不升版本；读端遇到未知 `kind` **跳过该行**，不报错
  （Go 侧 `ReadJSONL` 已如此实现，`TestJSONLUnknownKindSkipped` 锁死）。

**破坏性变更（必须升 `sitelens.graph/v2`）**
- 已有字段改名 / 语义改变 / 类型改变 / 删除。
- 读端遇到**主版本不匹配**（如 `v2`）必须**明确报错**，不得静默误读
  （Go 侧 `TestJSONLSchemaMismatch` 锁死；`compatibleSchema` 只接受 `v1` 前缀）。

**恒不变式（5.0 可依赖）**
1. 首行恒为 `kind=header` 且含 `schema`。
2. 每个实体恒有 `id`，形如 `<prefix>_<12hex>`。
3. `observation=positive` 的 `vuln_node` 恒有非空 `evidence_ids`。
4. `chain_edge` 恒有非空 `derived_from`，且其中每个 ID 指向图内 `evidence`。
5. 所有 `evidence_ids` / `derived_from` 引用**恒可在图内解析**（无悬空引用）。
6. `confidence=confirmed` 恒有证据支撑。

> 上述恒不变式由 `internal/model` 的 `Validate()` 强制（**唯一权威实现**），
> 并由 `internal/model/contract_test.go`（字面量契约与恒不变式）与
> `sitelens graph-read --self-test`（读端侧复验）验证。

## 9. 边界（5.0 只读）

- **5.0 ML 只读**本接口产出的结构化事实，**不反向写入/污染 4.0 执行链**：
  4.0 的扫描/审计路径不 import 任何 ML 产物，不读 `data/ml/`，不接受 ML 回灌。
- 4.0 分支**不含** `ml/` 代码；ML 流水线与依赖（`ml/requirements.txt`）属 5.0 分支。
- 数据本体（`data/state/graph/`）按 4.0 既有策略：`data/state/` 为运行期状态目录，
  不进 git；**schema/文档/参考读端**进仓。
