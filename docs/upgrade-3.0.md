# SiteLens v3.0.0 升级指南（v2.0.0 → v3.0.0）

## 1. 升级方式

| 场景 | 步骤 |
|---|---|
| 安装器版 | 直接运行 `SiteLens-3.0.0-setup-full.exe` 覆盖安装（历史数据保留） |
| 便携版 | 解压新版覆盖旧目录（保留旧目录的 `data/state/` 即可保留历史） |
| 源码版 | `git pull` 后 `go build ./cmd/sitelens` |

覆盖安装**不会**删除 `data/state/`（扫描历史、模板调度进度）。

## 2. 配置兼容性

- 旧 `.sitelens.yml` **无需修改**，全部键位向后兼容
- 新增可选配置段（不配置则用默认值，行为与 2.0 一致）：

```yaml
checks:
  workers: 16        # check 组级并行数（0 = 默认 12）
  nuclei_cap: 200000 # 模板调度上限（200000 = 全池 117,889 全跑）
exploit:             # 利用级验证，默认全关
  enabled: false
  authorized: []
  delay_threshold_ms: 3000
```

注意：v3 起 `nuclei_cap` 默认仍为 300，但调度器支持全池执行——
要全量跑请显式调高（如上）。

## 3. 数据迁移

- `data/state/history.json`、`nuclei_schedule.json`：无需迁移，直接沿用
- 模板索引缓存：首次扫描自动重建（schema v7，约 1-3 分钟，仅一次）
- 旧 `intel_dump.json.gz`（v2 的）：**建议替换**为 v3 剥离版（随 full 包/仓库分发），
  旧文件也可继续使用，但不含模板情报行数据面
- 新增可选文件：`data/tpl_intel.json.gz`（`update-tplintel` 生成）、
  `data/nvd_cves.json.gz`（`update-nvd` 生成）

## 4. 精简版（lite）如何补数据

```
sitelens update-nuclei     # 模板池（含协议族）
sitelens update-afrog      # afrog POC
sitelens update-fp <url>   # 社区指纹（可选）
sitelens update-ehole <path|url>  # 中文产品指纹（可选）
sitelens update-nvd        # NVD 字典全量（约 50 分钟，无 key 限速）
sitelens update-tplintel   # 模板情报行（依赖 NVD + 模板池）
```

## 5. API 变更（仅新增，无破坏）

- 新增 `GET /api/replay/{id}`：重放一次历史扫描
- verified 条目新增可选字段：`impact`、`impact_evidence`
- `/api/scan` 请求新增可选 `exploit` 布尔（需 config exploit.enabled）
- 其余端点与字段与 v2.0.0 完全一致

## 6. 回滚

1. 停止服务，换回 v2.0.0 二进制
2. `data/state/` 与历史文件无需处理（v2 可直接读取）
3. 若启用了 `exploit` 段，v2 配置文件中删除该段即可

## 7. 资源与时长变化

| 项 | v2.0.0 | v3.0.0 |
|---|---|---|
| 扫描时长（标准强度） | 基线 | 基本持平（模板调度 300 → 按配置） |
| 扫描时长（全量模板） | — | 随池规模增加，建议按强度分层 |
| 内存 | 基线 | +NVD 字典加载约 0.5-1GB（可配 `intel.nvd_path` 为空关闭） |
| 磁盘 | 基线 | +NVD 约 37MB + 模板情报约 3MB |

## 8. 如何验证升级成功

```
sitelens -version          # 输出 SiteLens 3.0.0
sitelens serve             # 启动日志应含「NVD 字典挂载」「模板情报行合并」
浏览器 → 情报页            # NVD 字典卡片显示 371,755
```
