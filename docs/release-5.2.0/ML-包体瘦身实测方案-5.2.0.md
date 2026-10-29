# ML 包体瘦身实测方案（5.2.0）

| 项 | 值 |
|---|---|
| 状态 | **方案 + 实测脚手架就绪；本轮未拍板、未改打包脚本、未改模型资产** |
| 关联缺陷 | [BUG-035](../../docs/bug清单-5.1.0.md)（安装包过大）、BUG-028（训练侧不可重建，见 §7） |
| 上游文档 | [升级规划-5.2.0](升级规划-5.2.0.md)（04 机器学习优化）、[release-body-5.2.0](release-body-5.2.0.md) §11 |
| 分支 | `feat/sitelens-5.2.0` |
| 编写日期 | 2026-10-29 |
| 测量代码 | [internal/ml/sev_onnx_int8_test.go](../../internal/ml/sev_onnx_int8_test.go)（`//go:build onnx`） |

> **一句话**：引擎侧「只带 int8」不需要改任何 Go 代码（模型 glob 已是 fp32→int8 回退），
> 现在缺的只是 int8 的精度代价数据。本文给出可在有 CGO 的机器上一键跑出的测量脚手架、
> 三条方案的费用/风险对比、建议门槛与决策矩阵。**本机 `CGO_ENABLED=0` 且无 gcc，
> 无法实跑 ONNX 推理，因此本文不含任何编造的精度实测数字**——凡精度数字均标注为
> 「待实测」并附命令；Python 侧已有记录的数字标明出处。

---

## 1. 现状体积（实测）

### 1.1 ML 资产逐文件（实测：2026-10-29，`Get-ChildItem models/go/ml_assets | Measure-Object Length -Sum`）

| 文件 | 字节数 | MiB（1024 进制） | 用途 | 推理必需？ |
|---|---:|---:|---|---|
| `sev-prior-v3.1-a.onnx` | 267,936,105 | 255.53 | sev-prior v3.1 种子 a（fp32） | 与 b 二选一套 |
| `sev-prior-v3.1-b.onnx` | 267,936,105 | 255.53 | sev-prior v3.1 种子 b（fp32） | 与 a 二选一套 |
| `sev-prior-v3.1-a-int8.onnx` | 69,334,437 | 66.12 | 种子 a 动态量化 int8 | 与 b 二选一套 |
| `sev-prior-v3.1-b-int8.onnx` | 69,334,437 | 66.12 | 种子 b 动态量化 int8 | 与 a 二选一套 |
| `cve-tech.coef.f32` | 94,080,000 | 89.72 | CVE→产品 OvR 系数（196×120k fp32） | 是 |
| `cwe-type.coef.f32` | 12,000,000 | 11.44 | CVE→CWE 类型系数（25×120k fp32） | 是 |
| `cve-tech.vocab.txt` | 1,645,303 | 1.57 | 线性模型词表 | 是 |
| `cwe-type.vocab.txt` | 1,540,950 | 1.47 | 线性模型词表 | 是 |
| `cve-tech.idf.f32` | 480,000 | 0.46 | 线性模型 idf | 是 |
| `cwe-type.idf.f32` | 480,000 | 0.46 | 线性模型 idf | 是 |
| `sev-prior-v3.1.vocab.txt` | 262,030 | 0.25 | sev 分词器词表 | 是（ONNX 方案） |
| `sev-fixtures.json` | 33,186 | 0.03 | sev 对拍夹具（120 条） | 否（仅测试） |
| `fixtures.json` | 238,630 | 0.23 | 线性模型对拍夹具（500 条） | 否（仅测试） |
| `cve-tech.meta.json` | 10,074 | 0.01 | 线性模型元数据 | 是 |
| `cwe-type.meta.json` | 1,203 | 0.00 | 线性模型元数据 | 是 |
| **合计（15 文件）** | **785,312,460** | **748.93** | | |

分组小计（同一实测口径）：

| 分组 | 字节数 | MiB | 占 ML 资产 | 占安装包 891.4 |
|---|---:|---:|---:|---:|
| 4 个 ONNX 合计 | 674,541,084 | 643.29 | 85.9% | 72.2% |
| ├ fp32 双模型 | 535,872,210 | 511.05 | 68.2% | 57.3% |
| └ int8 双模型 | 138,668,874 | 132.24 | 17.7% | 14.8% |
| 线性模型（cve-tech + cwe-type 全部文件） | 110,237,530 | 105.13 | 14.0% | 11.8% |
| └ 其中 coef.f32 两个 | 106,080,000 | 101.17 | 13.5% | 11.4% |
| sev 词表 + sev 夹具 | 295,216 | 0.28 | 0.04% | 0.03% |
| 线性对拍夹具 `fixtures.json` | 238,630 | 0.23 | 0.03% | 0.03% |

补充实测：仓库内已内置 `models/onnxruntime/onnxruntime.dll`，**16,462,648 字节（15.70 MiB）**——这份不算在 ML 资产的 748.93 MiB 里，但同属安装包成本。

### 1.2 与规划文档数字的对照

| 数字 | 规划文档口径 | 本文实测 | 说明 |
|---|---|---|---|
| 安装包/仓库合计 | 891.4 MB | —（未复测整包） | 来源：[BUG-035 实测构成表](../../docs/bug清单-5.1.0.md)、[升级规划 §04](升级规划-5.2.0.md) |
| ML 模型资产 | 748.9 MB（84%） | 748.93 MiB | 一致 |
| 4 个 ONNX 合计 | 643.3 MB | 643.29 MiB | 一致 |
| fp32 两份 | 511 MB | 511.05 MiB | 一致 |
| int8 两份 | 132 MB | 132.24 MiB | 一致 |

**单位口径说明**：仓库既有文档把 MiB 写作「MB」（`643.3MB` 实为 674,541,084 B ÷ 1024² = 643.29 MiB）。
本文一律先给**字节数（实测）**，再给 MiB；换算成十进制 MB 会分别变成 785.3 / 674.5 / 535.9 / 138.7 MB，
不改变任何结论，但引用时请注意不要混用。

---

## 2. 引擎与呈现现状（决定方案可行性的三条事实）

1. **「只带 int8」零代码改动即可生效**：[internal/engine/ml.go:93-98](../../internal/engine/ml.go)
   的模型清单按 `sev-prior-v3.1-[ab].onnx` → `sev-prior-v3.1-[ab]-int8.onnx` → 旧单文件（`:99-106`）
   的顺序 glob，fp32 对不存在时自动落到 int8 对；两者都在时优先 fp32。
   因此方案①在**运行时侧不需要动 `internal/ml` 或 `internal/engine` 的任何代码**，
   只需从分发清单移除 fp32 两件（打包脚本本轮未动，见 §9）。
2. **部署形态是双种子预测平均**：[internal/ml/sev_onnx.go:39-81](../../internal/ml/sev_onnx.go)
   一次加载多个 session，[`:85-118`](../../internal/ml/sev_onnx.go) 对每条文本取各 session
   logits 的算术平均 ×10 得到 CVSS 0-10 分并 clamp。所以「换成 int8」是把两个 session 的
   权重都换成量化版，两套都可在同一进程内并存（`ortOnce` 只保护运行时环境初始化，
   session 是 per-scorer 的）——这正是测量测试的可行性依据。
3. **呈现是「分数 ± 1.07 区间」，不是硬档位**：[web/app.js:544-546](../../web/app.js)
   把 `sev_score` 呈现为 `x.x ± 1.07（lo – hi）`（`:528` 注释同义）。因此
   **分数误差**才是主契约；CVSS 定性档/1 分档翻转属于诊断指标，不能单独当否决项
   （详见 §5.2）。

补充：无 onnx 构建下 [sev_onnx_stub.go](../../internal/ml/sev_onnx_stub.go) 让 `Score` 恒返回
`ErrNoONNX`，引擎回退 NVD CVSS 先验并落 `extras["ml_sev"]` 原因——所以「瘦身删到没有 ONNX」
在功能上只是精度降级到 NVD 先验，不是崩溃，这也让方案②的离线兜底语义成立。

---

## 3. 三条方案对比

> 方案①的「省 511.05 MiB」= 删掉 fp32 两件（实测字节数相减），终态包体按
> `891.4 MiB − 511.05 MiB` 推算，**属估算口径**；其余同理，标注了「推算」。

| # | 方案 | 包体（推算，按 891.4 MiB 口径） | Go 代码改动 | Python/打包改动 | 主要风险 | 实测依赖 |
|---|---|---:|---|---|---|---|
| ① | **int8 优先**：随包只带 int8 双模型（132.24 MiB），删 fp32 两件 | **380.35 MiB**（−511.05，−57.3%） | **0**（glob 已回退） | 分发清单移除 `-a.onnx`/`-b.onnx`；fp32 可改为「可选高级包」 | int8 精度损失未知（本文 §4 测的就是它） | 只需本测试通过门槛 |
| ② | **ONNX 按需下载**：首包不带 ONNX（只带线性模型 105.13 MiB 等），首次使用下载 int8 双模型 | 首包 **248.11 MiB**（−643.29，−72.2%）；首用下载 132.24 MiB，终态磁盘同① | 0（引擎已支持资产目录发生效；需补下载后的就绪判定，见 §6） | 下载器 + 托管 + SHA256 清单 + 离线/代理策略 | 首次使用需网络；完整性校验；离线部署需「离线包」出口 | 与精度无关，是工程/交付决策 |
| ③ | **线性系数压缩**：`cve-tech.coef.f32` + `cwe-type.coef.f32` 由 fp32 转 fp16（或稀疏化） | **840.82 MiB**（−50.58，−5.7%）；线性资产 105.13 → 54.55 MiB | 需改 Go 侧 `readF32` 与 `DecisionFunction` 精度路径 | 需改导出脚本、重出资产、重跑线性对拍（Top-1 ≥99.5%） | 收益最小却要动精度关键路径；fp16 是否会翻转 Top-1 未实测 | 需新增线性模型对拍 |
| ①+③ | 组合 | **329.77 MiB**（−63.0%） | 同上 | 同上 | 两处精度风险叠加，建议分两期 | — |

**附注④（可选杠杆，不在原三方案内）**：若产品接受「单种子部署」（放弃双种子平均集成），
int8 单件 69,334,437 B（66.12 MiB），方案①可再省 66.12 MiB → **314.23 MiB**。
代价：`docs/release-5.0.0/TRAINING_PARAMS.md` §3.9 记录「单模 test MAE 1.0722 / 双种子平均
集成 1.0699」，即集成收益仅 0.0023 分（0.2%）。**该杠杆改变模型契约，需产品拍板**，
本轮只记录不推荐。

---

## 4. 一键实测（在有 CGO 的机器上）

### 4.1 测什么

[internal/ml/sev_onnx_int8_test.go](../../internal/ml/sev_onnx_int8_test.go) 在同一进程内加载
**fp32 双模型**与**int8 双模型**两套 scorer（共 4 个 session），用同一个 `SevScorer.Score`
接口跑完 `sev-fixtures.json` 的全部夹具（当前 n=120，`ensemble="v3.1 a+b"`），输出三组对比
（全部为 CVSS 0-10 分尺度）与三类分档翻转率：

| 输出项 | 含义 | 用途 |
|---|---|---|
| `[自检] fp32(Go) vs 夹具真值` | Go fp32 与 Python 侧 fp32 集成真值的差 | 环境自检；TestSevOnnxParity 口径 <0.03，超出说明资产/分词器有问题 |
| `[量化] int8(Go) vs fp32(Go)` | **纯量化误差**（同分词器、同推理路径，只差权重精度） | **决策主依据** |
| `[端到端] int8(Go) vs 夹具真值` | 量化误差 + Go/Python 差异 | 对外解释用（谨慎引用） |
| `[翻转]` ×3 | 1 分档 / CVSS 定性档(4/7/9) / 显示位(0.1 分) 的翻转条数与比例 | 诊断（§5.2） |

### 4.2 前置条件

| 前置 | 要求 | 本机状态（实测） |
|---|---|---|
| CGO | `CGO_ENABLED=1` | ❌ `go env CGO_ENABLED` = **0** |
| C 编译器 | 能用 `gcc`（Windows 装 mingw-w64 并把 `bin` 加进 PATH） | ❌ `Get-Command gcc` 无结果 |
| onnxruntime 共享库 | `onnxruntime.dll` | ✅ 仓库已内置 `models/onnxruntime/onnxruntime.dll`（16,462,648 B） |
| ONNX 资产 | 4 件（fp32 a/b + int8 a/b）、`sev-prior-v3.1.vocab.txt`、`sev-fixtures.json` | ✅ `models/go/ml_assets/` 齐全（见 §1.1） |
| 内存 | 4 个 session 常驻约 **1.2 GiB** | 建议 ≥8 GB 机器 |
| 时间 | CPU 120 条 × 4 模型，约 1–3 分钟（视 CPU）；session 加载数秒 | — |
| 网络 | **不需要**（Go 依赖已 vendor） | ✅ |

### 4.3 命令（PowerShell，仓库根目录执行）

```powershell
# 1) 打开 CGO（需 gcc 在 PATH；否则下一步会报 cgo: C compiler "gcc" not found）
$env:CGO_ENABLED = "1"
# 2) 共享库：不设则自动找 data/onnxruntime → models/onnxruntime（本仓内建后者）
$env:SITLENS_ORT_DLL = "<仓库根>\models\onnxruntime\onnxruntime.dll"  # 也可不设，测试会自动探测
# 3) 测量机建议加上这句：前置缺失时「失败」而不是「跳过」，避免跳过被当成通过
$env:SITLENS_INT8_MEASURE_REQUIRED = "1"
# 4) 跑（-run 只为跳过同包其它用例、省内存；-timeout 留足 10 分钟）
go test -tags onnx ./internal/ml -run TestSevOnnxInt8VsFp32 -v -count=1 -timeout 10m
```

可选环境变量：

| 变量 | 默认 | 作用 |
|---|---|---|
| `SITLENS_ORT_DLL` | 自动探测 | onnxruntime 共享库路径 |
| `SITLENS_INT8_MEASURE_REQUIRED` | 空（跳过） | `1` = 前置缺失时判失败（测量机/CI 用） |
| `SITLENS_INT8_MAX_MAE` | `0.30` | 灾难上界（CVSS 分）；推荐门槛不在此断言，见 §5 |

### 4.4 预期输出（**结构示意，非实测数字**）

```
=== RUN   TestSevOnnxInt8VsFp32
    资产 sev-prior-v3.1-a.onnx                  267936105 B ( 255.53 MiB)
    ...
    四件 ONNX 合计 674541084 B (643.29 MiB)；预期 fp32 对 511.0 MiB + int8 对 132.2 MiB
    夹具 n=120 ensemble="v3.1 a+b"（真值 = Python 侧 fp32 双模型集成 ×10 CVSS 分）
    加载 fp32 双模型（约 536 MiB 权重）…
    int8 双模型就绪；两套 session 常驻（总加载 <时长>，内存约 1.2GiB）
    推理耗时（双模型各一次、取平均）：fp32 共 <时长>；int8 共 <时长>
    [自检] fp32(Go) vs 夹具真值: n=120 MAE=<待实测> max=<待实测>（TestSevOnnxParity 口径 <0.03）
    [量化] int8 vs fp32（纯量化误差）: n=120 MAE=<待实测> RMSE=<待实测> max=<待实测> p95=<待实测>
           绝对误差分布：>0.1 分 <n> 条 / >0.3 分 <n> 条 / >0.5 分 <n> 条 / >1.0 分 <n> 条
           折算 logits(0-1) 尺度 MAE=<待实测>（Python 导出闸门 int8<0.05，实测 0.0127，来源 TRAINING_PARAMS.md §3.9）
    [端到端] int8(Go) vs 夹具真值: n=120 MAE=<待实测> max=<待实测> p95=<待实测>
    [翻转] 1 分档               int8 vs fp32: <n>/120 = <x>%
    [翻转] CVSS 定性档(4/7/9)    int8 vs fp32: <n>/120 = <x>%
    [翻转] 显示位 0.1 分          int8 vs fp32: <n>/120 = <x>%
    [样例] int8 vs fp32 绝对误差最大的 5 条： …
    结论：纯量化 MAE=<待实测> 分 < 灾难上界 0.30 分，通过。推荐门槛：MAE≤0.15 且 p95≤0.30 且 max≤0.60 → 方案① …
--- PASS: TestSevOnnxInt8VsFp32
```

把 `MAE / p95 / max / 翻转率` 四项抄进 §5 的决策矩阵即可得出结论。**夹具文本与真值都随仓库分发
（`models/go/ml_assets/sev-fixtures.json`），同一份资产在别人的机器上应得到同一数量级的结果。**

### 4.5 当前本机实测状态（如实记录）

| 检查 | 命令 | 结果 |
|---|---|---|
| 无标签单测（不被新测试影响） | `go test ./internal/ml -count=1` | ✅ `ok … 0.321s` |
| 带 onnx 标签编译/运行 | `go test -tags onnx ./internal/ml -run TestSevOnnxInt8VsFp32 -v` | ❌ `FAIL [setup failed]`：`imports github.com/yalue/onnxruntime_go: build constraints exclude all Go files in …\vendor\github.com\yalue\onnxruntime_go`（CGO_ENABLED=0 的正常表现） |
| 测试文件静态检查 | `gofmt -l` / 临时模块 `go vet -tags onnx`（用 ORT stub 类型检查并空跑统计逻辑） | ✅ 无格式差异、vet 通过、统计/翻转/日志逻辑在假分数下跑通（**仅校验代码路径，不产生精度结论**） |

---

## 5. 建议门槛与决策矩阵

### 5.1 主门槛：纯量化误差（`[量化] int8 vs fp32`，CVSS 0-10 分）

| 条件（全部为待实测） | 判定 | 建议动作 |
|---|---|---|
| `MAE ≤ 0.15` 且 `p95 ≤ 0.30` 且 `max ≤ 0.60` | **通过** | **方案① int8 优先**：随包只带 int8 双模型，fp32 转「可选高级包/按需下载」，包体 891.4 → 380.35 MiB |
| `MAE ≤ 0.15` 但 `p95 > 0.30` 或 `max > 0.60`（长尾差） | 条件通过 | 先看日志里「误差最大的 5 条」：若都是同一类文风（如超短描述、表格化描述）可接受；否则按灰区处理 |
| `0.15 < MAE ≤ 0.30` | 灰区 | 走 **①+② 混合**：随包带 int8（省 511.05 MiB），fp32 改为按需下载供复核；同时把「显示位翻转率」写进发布说明 |
| `MAE > 0.30` | **不通过** | **方案② 按需下载**：首包 248.11 MiB，默认仍下 int8，fp32 作校验通道；int8 是否上线另议 |

**为什么门槛取 0.15 分**：

1. 呈现契约是 `sev_score ± 1.07`（[web/app.js:544-546](../../web/app.js)），模型自身 test MAE 为
   1.07/1.0699（[TRAINING_PARAMS §3.9](../../docs/release-5.0.0/TRAINING_PARAMS.md)）。
   0.15 分 = 呈现误差的 **14%**、模型误差的 **14%**、0-10 量程的 **1.5%**——量化误差不应占主导。
2. Python 侧对部署对（双种子集成 fp32 vs int8）已记录 **MAE 0.0127 logits = 0.127 分**，
   闸门 `< 0.05 logits`（TRAINING_PARAMS §3.9；代码闸门见 `ml/export_sev_v31_pair.py:111-112`）。
   若 Go 侧复测落在同量级，则 MAE≈0.13 ≤ 0.15，直接落入推荐①区间。
3. `max ≤ 0.60` 用来防「均值好看但个别条目差 1 分」——单条最多影响显示的最后一位小数两档，
   仍远小于 ±1.07 的呈现带。

### 5.2 次门槛：分档翻转率（**诊断项，不单独否决**）

理由：5.x 的 sev-prior 呈现是分数 ± 区间、不做硬档位（§2 事实 3），故翻转率不直接改变用户看到的东西；
它主要用于判断「是否有下游消费方把 `sev_score` 映射成定性档/整数档」。

| 指标 | 可忽略 | 触发人工复核（看日志样例） | 说明 |
|---|---|---|---|
| CVSS 定性档（4/7/9）翻转率 | ≤ 5%（≤6/120） | > 10%（>12/120） | 边界附近条目正常晃动；若翻转集中在 4.0/7.0/9.0 附近可接受 |
| 1 分档翻转率 | ≤ 5%（≤6/120） | > 10%（>12/120） | 同上 |
| 显示位（0.1 分）翻转率 | **预期会很高**（MAE≈0.13 已大于 0.1 的显示步长） | 不设阈值 | 呈现粒度问题，不是精度事故；建议发布说明写明「分数可能有 ±0.1 抖动」 |

**样本量提醒**：夹具 n=120，1 条 = 0.83%，MAE 的 95% 置信区间较宽。
**最终拍板前建议把夹具扩到 ≥500 条再做一次**（扩样需改 `ml/export_sev_v31_pair.py` 的文本清单并重生成
`sev-fixtures.json`，本轮未做，见 §6）。

### 5.3 无论选哪条，都建议保留

- **fp32 仍可获取**：可选下载包 + SHA256 清单（与 ONNX 资产同版本号），供「精度投诉/复核」出口；
- **资产校验**：下载后校验 SHA256 + 文件大小（大小已知，见 §1.1，可作为第一道完整性检查）；
- **降级可解释**：ONNX 不可用时引擎已回退 NVD 先验并写 `extras["ml_sev"]` 原因（§2 补充），
  瘦身后不要丢这条链路。

---

## 6. 未决事项（需拍板 / 需另立任务）

1. **是否接受删 fp32**：方案①一旦删掉随包 fp32，离线用户就没有高精度版本可切；要不要提供
   「可选高级包」下载（决策依赖 §4 实测结果）。
2. **方案②的交付工程细节**（若走②）：下载源与托管、SHA256 清单与签名、离线部署的「离线包」出口、
   企业代理/内网场景、首用时机（启动即下 vs 首次扫描时下）。
3. **夹具扩样**（n=120 → ≥500）：为把 MAE 置信区间收紧到可用于发布门槛；需改
   `ml/export_sev_v31_pair.py` 的文本来源并重生成夹具（属训练/导出侧改动，本轮未动）。
4. **仓库内 int8 消融数字口径待澄清**：`ml/export_sev_v31_pair.py:80-81` 注释记「全量化 MAE 0.203 /
   排除分类头 0.196」，未标尺度；若为 CVSS 分则等于 0.0203/0.0196 logits（与 §3.9 的 0.0127 同量级），
   若为 logits 则与 §3.9 矛盾。本文主引用 §3.9 的部署对记录；建议重训/重导时顺手在脚本里把尺度写死。
5. **打包脚本改动另立任务**：`desktop/build-engine.js`、`tools/wails_build.sh`、`desktop-wails/main.go`
   都涉及交付清单，本轮**一行未改**（见 §9）。
6. **偏差杠杆④（单种子部署）**：需产品确认是否接受放弃双种子集成（省 66.12 MiB，集成收益 0.0023 分）。

---

## 7. 训练侧前置条件（BUG-028，供重训/重导 int8 使用）

要「重训 + 重新导出 int8」来复测，先得能在本仓跑通训练链路。BUG-028（训练侧不可重建）
本轮已修：

| 项 | 修前 | 修后 |
|---|---|---|
| `ml/requirements.txt` | 只有 numpy/pandas/scikit-learn/pytest，sev 训练 import torch/transformers 必失败 | 补 `torch`、`transformers`（带用途注释；导出/对拍用的 `onnx`/`onnxruntime` 作为可选依赖单列），**不固定版本**（仓库无 lock，如实记录） |
| 训练脚本数据路径 | 15 个脚本把开发者机器绝对路径 `D:\fengqiao\Desktop\26-08python实训\…` 写死为 `--data-root` 默认值（`train_sev_v31_deploy.py` 写死在 `ap_args` 里），本仓无法重训 | 全部改为 `default=None`，由 `ml/config.py` 统一解析：**环境变量优先 → 仓库相对默认** |
| 预训练底座路径 | `--base-model` 默认 `data\bench\models\...`（依赖 cwd） | `default=None` + `SITLENS_ML_ASSETS`（默认 `<repo>/data/bench/models`），与 cwd 无关 |
| 其余相对默认 | `--prev-model`/`--primary-model`/`--msf-json`/`--farm-history` 均为 cwd 相对路径 | 分别走 `config.ml_artifact()` / `config.bench_asset()` / `config.farm_history()`（默认仓库相对，可用 `SITLENS_ML_GO_ASSETS` / `SITLENS_ML_BENCH` / `SITLENS_FARM_HISTORY` 覆盖） |
| 导出脚本输出 | `export_go_assets.py` / `export_sev_v31_pair.py` 写死开发机路径 | 输出走 `SITLENS_ML_GO_ASSETS`（默认 `<repo>/data/go/ml_assets`）；权重/底座走 `SITLENS_ML_OUT` / `SITLENS_ML_ASSETS` |

环境变量一览（详见 `ml/config.py` 头部注释）：

| 变量 | 默认（仓库相对） | 用途 |
|---|---|---|
| `SITLENS_DATA_ROOT` | `<repo>/data`（须含 `state/history.json`） | 原始 KB 数据根 |
| `SITLENS_ML_OUT` | `<repo>/data/ml` | 产物根（dataset/experiments/metrics/dist） |
| `SITLENS_ML_ASSETS` | `<repo>/data/bench/models` | 预训练底座权重根（`distilbert-base-uncased/`） |
| `SITLENS_ML_BENCH` | `<repo>/data/bench` | 基准/外部资产根（`models/`、`external/` 的上一级） |
| `SITLENS_ML_GO_ASSETS` | `<repo>/data/go/ml_assets` | Go 引擎资产导出目录 |
| `SITLENS_FARM_HISTORY` | `<SITLENS_DATA_ROOT>/state/history.json` | 靶场扫描历史（仅 EXP-1101/1102） |

复现 int8 两件的完整链路（**需 GPU + 已备数据；本轮不执行训练**）：

```bash
# 1) 部署重训（双种子 20260928/20260929，2 epochs，Huber；产出 s<seed>.pt ×2）
python -m ml.train_sev_v31_deploy
# 2) 导出 fp32 + int8 + 重生成 sev-fixtures.json（CPU 可跑，需 onnx/onnxruntime）
python -m ml.export_sev_v31_pair
# 3) 回到 §4.3 跑 Go 侧测量
```

注意：训练脚本在 CUDA 不可用时直接 `[abort]`（不做 CPU 假跑，见 `ml/train_sev_v31_deploy.py` 文件头），
所以第 1 步必须在有 GPU 的机器上；第 2、3 步 CPU 即可。

---

## 8. 数字来源清单

| 数字 | 值 | 来源（可复核） |
|---|---|---|
| 安装包/仓库合计 | 891.4 MB | `docs/bug清单-5.1.0.md` BUG-035 实测构成表；`docs/release-5.2.0/升级规划-5.2.0.md` §04 |
| ML 资产合计 | 748.9 MB（84%） | 同上；本文实测 785,312,460 B = 748.93 MiB |
| 4 个 ONNX 合计 | 643.3 MB | 同上；本文实测 674,541,084 B = 643.29 MiB |
| 各文件字节数 | §1.1 表 | 实测：`Get-ChildItem models/go/ml_assets -File \| Measure-Object Length -Sum`（2026-10-29） |
| `onnxruntime.dll` | 16,462,648 B | 实测：`models/onnxruntime/onnxruntime.dll` |
| Python 侧 int8 对拍 | MAE 0.0127（logits 尺度）< 0.05 闸门 | `docs/release-5.0.0/TRAINING_PARAMS.md` §3.9（2026-09-29 部署重训记录）；代码闸门 `ml/export_sev_v31_pair.py:111-112` |
| Python 侧导出闸门 | fp32 MAE<0.02、int8 MAE<0.05（logits） | `TRAINING_PARAMS.md` §3.1（ONNX 导出条目）；`ml/export_sev_v31_pair.py:10` |
| 单模/集成 test MAE | 1.0722 / 1.0699 | `TRAINING_PARAMS.md` §3.9 |
| 引擎模型 glob 顺序 | fp32 → int8 → 单文件 | `internal/engine/ml.go:93-106` |
| 集成平均口径 | logits 平均 ×10，clamp 0-10 | `internal/ml/sev_onnx.go:85-118` |
| 呈现「分数 ± 1.07」 | — | `web/app.js:528,544-546` |
| 夹具规模 | n=120，seq=192，ensemble="v3.1 a+b" | 实测：`models/go/ml_assets/sev-fixtures.json` 顶层字段 |
| **Go 侧 int8 vs fp32 精度数字** | **待实测** | 本机无 CGO/gcc 无法执行；命令见 §4.3，测试见 `internal/ml/sev_onnx_int8_test.go` |

> 本机环境实测（供复核）：`go env CGO_ENABLED` = `0`；`Get-Command gcc` 无结果；
> `go test -tags onnx ./internal/ml` 报 `build constraints exclude all Go files in …\vendor\github.com\yalue\onnxruntime_go`。

---

## 9. 本轮做了什么 / 没做什么

**做了**：

- 新增 `internal/ml/sev_onnx_int8_test.go`（`//go:build onnx`）：fp32 双模型 vs int8 双模型同进程测量，
  输出三组误差 + 三类分档翻转率 + 最坏样例，默认只拦 `MAE ≥ 0.30` 的灾难上界；
  资产/DLL 缺失时 `t.Skip`，**不影响无标签构建**（`go test ./internal/ml` 实测仍 ok）。
- 新增本文档（体积实测表、三方案对比、一键命令、建议门槛与决策矩阵、来源清单）。
- 修 BUG-028：`ml/requirements.txt` 补 torch/transformers；训练/导出脚本去绝对路径，
  统一走 `SITLENS_*` 环境变量 + 仓库相对默认（§7）。

**没做（明确不在本轮）**：

- ❌ 未改 `models/` 下任何模型资产（未删、未压缩、未重命名）；
- ❌ 未改打包/发版脚本：`desktop/build-engine.js`、`tools/wails_build.sh`、`desktop-wails/main.go`、
  安装器清单等**一行未动**；
- ❌ 未改 `internal/ml` 既有非测试代码（`sev_onnx.go` 的 `ortOnce` 单例语义已支持多 scorer 并存，无需改）；
- ❌ 未跑任何 ONNX 推理、未产生任何精度实测数字；
- ❌ 未实际训练模型、未重出资产；
- ❌ 未 `git add` / `commit` / `push`；方案未拍板。
