# 升级指南：4.0.0 / 4.0.1 → 5.0.0

## 升级前

| 检查项 | 说明 |
|--------|------|
| 磁盘空间 | 安装包约 552MB（ML 模型资产全量内嵌），安装后占用约 1.1GB |
| 操作系统 | Windows 10/11 x64（与 4.x 相同） |
| 运行中的扫描 | 等待完成或取消后再升级（安装器会替换引擎文件） |
| 授权目标 | 5.0 新增 `target.allow_private` 开关：默认 false，扫内网/本机靶场需自行开启并自担合规；gov.cn 与云 metadata 端点永久阻断 |

## 升级步骤

1. 下载 SiteLens-Setup-5.0.0.exe，核对 SHA256：
   `9f4965cabb50be73bd5654ad3fc2523bd9577b8c3ca206fe2fd84e6632edb556`
2. 直接运行安装器（自动覆盖升级，无需卸载 4.x；用户配置与历史记录保留于
   `%APPDATA%`，不受影响）。
3. 启动后确认版本：工作台关于页 / 引擎命令行 `-version` 应显示 5.0.0。
4. 已安装 4.x 的「检查更新」也可完成升级（增量 blockmap 或全量包）。

## 5.0 新增配置（均为可选，默认即合理）

配置文件 `ml:` 节新增：

```yaml
ml:
  predict: true        # ML 总闸：默认开。关掉 = 回到纯 4.0 行为
  assets_dir: data/go/ml_assets
  sev_onnx: true       # 桌面版默认 true：sev_score 走 sev-prior 模型推理
  onnxrt_dll: data/onnxruntime/onnxruntime.dll
```

- `predict: false`：关闭全部 AI 行为（先验调度 + 预测富化），引擎行为与
  4.0 逐字节一致。
- `sev_onnx: false`：仅关闭严重度模型推理，sev_score 回退 NVD CVSS 先验。

npm 分发线（`@fengqiao666/sitelens-cli` 0.0.1-rc）为独立安装形态，与桌面
安装器互不影响：

```bash
npm install -g @fengqiao666/sitelens-cli
sitelens          # 交互式 TUI
sitelens scan <url> --level deep
```

## 升级后验证

1. 任意目标扫一次 standard 或 deep 档位。
2. 工作台结果页应出现「AI 预测」块（有含 CVE 的发现时）；摘要区出现
   「AI 产品先验」行（当模型对目标给出有效先验时）。
3. 预测表中「来源」徽章：桌面版应显示「模型推理」（onnx）；显示「NVD 先验」
   且摘要下方有降级说明时，按说明检查 `ml:` 配置与资产路径。

## 回滚

直接安装 4.0.1 安装器即可回滚（覆盖式安装）。5.0 写入的用户配置与新字段
不会被 4.0 读取，但也不造成冲突；历史记录双向兼容（5.0 新增字段对 4.0
不可见）。

## 问题反馈

升级遇到问题请在仓库 Issue 提交，附：引擎 `-version` 输出、`ml:` 配置节、
扫描结果 JSON 的 `extras.ml_sev` 字段（如有）。
