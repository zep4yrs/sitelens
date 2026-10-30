# 阶段 1：线性 severity 上线、ONNX 退出默认分发（5.2.0）

> 状态：**代码/资产/打包/测试已落地（工作区改动，未 commit）**。
> 关联：`BUG-035 包体瘦身`、[ML-算法替代 A/B 实验](ML-算法替代A-B实验-5.2.0.md)、
> [ML-包体瘦身实测方案](ML-包体瘦身实测方案-5.2.0.md)。
> 实验与收益口径见 A/B 报告；本文只记录「落地了什么、契约是什么、怎么验」。

---

## 1. 一句话

删掉随包分发的 sev-prior ONNX（643.3 MiB）与 onnxruntime.dll（15.7 MiB），
严重度默认改为 **NVD/情报行查表（误差 0）→ `sev-linear` 线性回归兜底（0.7MB，留出 MAE 1.180）**；
同一批 600 条 NVD 抽样上，transformer 1.079 vs 线性 1.189（**+0.11 分，10%**），
仍小于呈现带 ±1.07，显示层几乎无感。安装包 ML 资产从 748.9 MiB 降到约 106 MiB。

---

## 2. 资产契约：`sev-linear`

由 [`ml/train_sev_linear.py`](../../ml/train_sev_linear.py) 训练 + 导出（纯 numpy，CPU ~25s），
产物落在 `models/go/ml_assets/`：

| 文件 | 内容 | 实测体积 |
|---|---|---|
| `sev-linear.vocab.txt` | 一元词表（41,384 行，行号=特征 id） | 319 KiB |
| `sev-linear.idf.f32` | smooth idf（float32 LE） | 162 KiB |
| `sev-linear.coef.f32` | 1×N 回归系数（float32 LE，行主序） | 162 KiB |
| `sev-linear.meta.json` | 与 cve-tech/cwe-type 同构；`n_classes=1`、`intercept` | <1 KiB |
| `sev-linear-fixtures.json` | 120 条 NVD 真值夹具（Go 回归测试用） | 36 KiB |

> 合计 694,315 B ≈ **0.69 MB**（LF 资产口径，`.gitattributes` 的 eol=lf 会归一换行）。

**推理口径（与 Go `internal/ml/ml.go` 逐位一致）**：小写 → `(?u)\b\w\w+\b` 一元词 →
`(1+ln tf)·idf` → L2 归一 → `score = x·w + b` → clamp [0,10]。
训练/测试：pub<2024 全量训练（220,745 条），pub≥2024 抽 20,000 条做留出；
夹具取自留出池外另一批 120 条（seed 20261031，不同批次）。

**复现**：`python ml/train_sev_linear.py`（可用 `SITLENS_NVD_DUMP` / `SITLENS_ML_GO_ASSETS`
覆盖路径；默认读仓库内 `data/nvd_cves.json.gz`）。

---

## 3. 引擎接线

严重度后端优先级（`internal/engine/ml.go` 的 `mlEnrich`）：

```
NVD 镜像/情报行已有 CVSS 分  → SevSource="nvd"（查表，误差 0）
        ↓ 查不到
sev_linear（默认开）        → SevSource="linear"（0.7MB 线性回归）
        ↓ 资产缺失/损坏
可选 sev_onnx 高级包          → SevSource="onnx"（±1.07，默认关）
        ↓ 都没有
无先验（SevSource 空、不输出 sev_score）
```

- 配置：`ml.sev_linear`（默认 **true**）、`ml.sev_onnx`（默认 **false**，可选高级包）、
  `ml.onnxrt_dll`（仅高级包使用）。设置页同步增加「线性严重度兜底」开关。
- `predictions[].sev_source` 取值新增 `linear`；`extras.ml_sev` 改为来源计数
  `{active, nvd, linear, onnx, none, reason?, linear_reason?}`，web 摘要区按来源分行展示。
- 可选资产加载语义（`internal/ml/assets.go`）：四件缺失 = 未就绪（不报错、不置死）；
  文件齐全但损坏/非单输出回归 = 仅禁用该后端，cve-tech/cwe-type 仍可用。

---

## 4. 打包与体积

| 项 | 5.1/5.2 旧形态 | 阶段 1 默认包 | 可选 ONNX 高级包 |
|---|---|---|---|
| sev-prior ONNX（fp32 双种子 + int8） | 643.3 MiB | **0** | 643.3 MiB（fp32 双种子） |
| onnxruntime.dll | 15.7 MiB | **0** | 15.7 MiB |
| 线性模型（cve-tech + cwe-type + sev-linear） | 105.1 MiB | **约 106.1 MiB** | 同左 |
| ML 资产合计 | 748.9 MiB | **约 106.1 MiB（-86%）** | 854.7 MiB |
| 引擎载荷（实测出包） | 约 840 MiB（旧 staging 推算） | **173.8 MiB（-79.3%）** | ≈840 MiB |
| 安装包（估算） | 744 MiB（5.1.0 实测） | **约 126 MiB（-83%）** | 待回填 |

> 安装包估算口径：`desktop/engine` 载荷（173.8 MiB，本机无 C 工具链为 AST 降级构建；
> 2026-10-30 数据刷新后实测，NVD 种子 30.7 MiB）
> + Wails 壳（11.9 MiB）用 7-Zip LZMA2 solid 压缩实测 ≈125.7 MiB，加 NSIS 头/开销后
> 约 **126 MiB**；正式包带白盒 AST（CGO）时引擎二进制会再大几 MiB～十几 MiB，
> 预计 **133–143 MiB** 量级。真实安装包体积以出包为准（`【待发布】` 回填）。

- `desktop/build-engine.js`：默认**不加** `-tags onnx`、资产进箱时过滤
  `sev-prior*.onnx`、不装 onnxruntime.dll；新增硬闸要求 `sev-linear` 四件齐全
  （缺失直接出包失败，避免残包把降级藏到用户机器上）。
- 高级包：`SITLENS_BUNDLE_ONNX=1 node build-engine.js --target=engine` 恢复旧契约
  （-tags onnx + ONNX 资产 + dll），用户在设置页打开 `sev_onnx` 后生效。
- 桌面壳种子配置（`desktop/engine.js`）：`sev_linear: true, sev_onnx: false`。
- **仓库瘦身已落地（5.2，独立动作）**：`onnxruntime.dll` / `sev-prior*.onnx` 已从
  仓库与 git 历史中移除（含 LFS 对象），完整 clone 从约 1.35 GB 降到约 0.5 GB；
  高级包出包前需手动把资产放入 `models/`，见[仓库瘦身-5.2.0](仓库瘦身-5.2.0.md)。

---

## 5. 验收记录（本机实测）

| 项 | 命令 | 结果 |
|---|---|---|
| 编译 | `CGO_ENABLED=0 go build ./...` | ✅ exit 0 |
| 线性 severity 夹具门禁 | `go test ./internal/ml -run TestSevLinearFixtures -v` | ✅ n=120 **MAE=1.0858 / max=5.24**（守卫阈值 1.30） |
| 边界守卫 | `go test ./internal/ml -run 'TestRegressionScoreGuards\|TestLoadOptionalSevLinear'` | ✅ 维度/NaN/clamp/可选加载语义全过 |
| 引擎后端优先级 | `go test ./internal/engine -run 'TestML\|TestSev'` | ✅ 11 用例全过（含 nvd→linear 优先级、关闭开关不臆造分数） |
| 配置/设置 | `go test ./internal/config ./internal/server -run 'TestSettings'` | ✅ 通过（含 `sev_linear/sev_onnx` 默认值与 YAML 覆盖用例） |
| 打包 dry-run | `node desktop/build-engine.js --target=engine` | ✅ 59 个文件 **173.8 MB**；无 `*.onnx`/`onnxruntime.dll` 进箱，`sev-linear.*` 就位 |
| 静态检查 | `go vet ./internal/ml ./internal/engine ./internal/config ./internal/server` | ✅ exit 0 |
| 前端语法 | `node --check web/js/app.js` / `settings.html` 内联脚本 | ✅（见 CI 前端回归） |

> 引擎载荷 173.8 MiB 为 `node desktop/build-engine.js --target=engine` 实测（59 文件；
> 2026-10-30 数据刷新后）；
> 安装包 126 MiB / 旧 744 MiB 的口径见上表注脚，最终数字以真实出包回填。

---

## 6. 明确未做 / 后续

- ✅ 仓库内 ONNX/LFS 资产已删除（5.2 仓库瘦身，含 git 历史重写），见[仓库瘦身-5.2.0](仓库瘦身-5.2.0.md)。
- ❌ 未改 cve-tech/cwe-type 能力本身（阶段 2：查表优先 + 词典前置/线性兜底，见 A/B 报告）。
- ❌ 未扩 500 条夹具（阶段 1 用 120 条 Go 门禁 + 2 万留出评测；扩样列入 5.3）。
- ❌ 未跑真实安装包构建与 LZMA 体积回填（本机无打包依赖，脚本逻辑已按 dry 检查）。
- 回退方案：保留 `ml.sev_onnx` 开关与 ONNX 代码路径；用户可装高级包并打开，
  或直接把 `sev_linear` 关掉只信 NVD 查表。

---

## 7. 决策依据（A/B 摘要）

同一 600 条 NVD 抽样（pub≥2024，真值=score，算法只读描述）：

| 方案 | MAE | 4 档准确率 | 资产 |
|---|---:|---:|---|
| sev-prior fp32 双种子（旧） | 1.079 | 60.8% | 536 MiB + dll |
| **sev-linear 线性回归（新默认兜底）** | **1.189** | — | **0.7 MiB** |
| 手写 CVSS 3.1 公式规则 | 1.427 | 48.8% | 0 |
| 常数均值 | ≈1.40 | — | 0 |

查表覆盖率：tpl_intel 29,536/29,554 = **99.94%**、vuln_kb 724/729 = **99.31%** 的
输入在 NVD 已有分数——对这部分输入，查表误差 0，任何模型都是多余产能；
真正的盲区只有「本地 NVD 快照未同步到的新 CVE」。完整方法与全部数字见
[ML-算法替代 A/B 实验](ML-算法替代A-B实验-5.2.0.md)。
