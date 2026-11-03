// Package diag 生成本机脱敏诊断包，并可选地提交到**用户自建**的收集端点。
//
// 为什么有它：5.2 规划期用户反馈「失败了没有反馈信息、也没有反馈入口」。
// 但产品已明确承诺**无埋点、无遥测、无崩溃上报**（写在《用户服务协议》里）——
// 那是隐私卖点，不是遗漏。故此处取折中：
//
//	诊断包在**本机**生成 → 内容脱敏 → 用户自己决定带不带
//	提交目标由用户自己配（默认空 = 不提交，只能复制到 Issue）
//
// 因此本包**不含任何常驻采集逻辑**：不联网、不上报、不写用户目录。
package diag

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/ml"
)

// Asset 数据资产就位情况。
type Asset struct {
	Name    string `json:"name"`    // 资产名（如「指纹库」）
	Path    string `json:"path"`    // 脱敏后的路径（只给文件名，不给绝对路径）
	Present bool   `json:"present"` // 是否就位
	SizeKB  int64  `json:"size_kb"` // 体积（KB）
	Note    string `json:"note"`    // 缺失时受影响的���力说明
}

// Report 诊断包（结构化 + 可直接粘贴的纯文本）。
type Report struct {
	GeneratedAt  string            `json:"generated_at"`
	Version      string            `json:"version"`
	Platform     string            `json:"platform"`
	Runtime      map[string]string `json:"runtime"`
	Config       map[string]any    `json:"config"`
	Assets       []Asset           `json:"assets"`
	Degraded     []string          `json:"degraded"`
	RecentErrors []string          `json:"recent_errors"`
	Text         string            `json:"text"`
}

// Build 组装诊断包。
//
// version   引擎版本号
// cfg       当前配置（仅取脱敏摘要，**不含 token 与凭证**）
// recentErr 最近的失败记录（来自扫描历史）
func Build(version string, cfg *config.Config, recentErr []string) *Report {
	r := &Report{
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05"),
		Version:      version,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		Runtime:      runtimeInfo(),
		Config:       ConfigSummary(cfg),
		Assets:       Assets(cfg),
		RecentErrors: recentErr,
	}
	for _, a := range r.Assets {
		if !a.Present && a.Note != "" {
			r.Degraded = append(r.Degraded, a.Name+"：缺失（"+a.Note+"）")
		}
	}
	sort.Strings(r.Degraded)
	r.Text = r.renderText()
	return r
}

func runtimeInfo() map[string]string {
	return map[string]string{
		"go_version": runtime.Version(),
		"num_cpu":    fmt.Sprint(runtime.NumCPU()),
		"os_arch":    runtime.GOARCH,
		"os":         runtime.GOOS,
	}
}

// Assets 检查配置引用的数据资产是否就位，并标出各自缺失时受影响的能力。
//
// 这是诊断包最有价值的部分：用户报"某某功能没结果"时，多半是**某个资产
// 缺失导致该能力静默降级**——这里直接给出对照表。
func Assets(cfg *config.Config) []Asset {
	if cfg == nil {
		return nil
	}
	items := []struct {
		name string
		path string
		dir  bool
		note string
	}{
		{"指纹库", cfg.Intel.TechnologiesPath, false, "指纹识别结果为空"},
		{"精选漏洞情报库", cfg.Intel.DumpPath, false, "漏洞情报关联与 KEV 在野利用标记失效"},
		{"受影响版本区间", cfg.Intel.RangesPath, false, "情报三级判定只能给 possible"},
		{"NVD CVE 字典", cfg.Intel.NVDPath, false, "CVSS 评分补全与 CPE 关联通道失效"},
		{"模板情报行", cfg.Intel.TplIntelPath, false, "模板 possible→confirmed 的关键链路失效"},
		{"模板池", cfg.Checks.NucleiDir, true, "Nuclei 模板子集完全不运行"},
		{"ML 模型资产", cfg.ML.AssetsDir, true, "ML 先验与严重度预测静默跳过"},
		{"字典目录", cfg.Active.WordlistDir, true, "目录/子域/爆破探测词表缺失"},
	}
	out := make([]Asset, 0, len(items))
	for _, it := range items {
		a := Asset{Name: it.name, Path: maskPath(it.path), Note: it.note}
		if it.path == "" {
			a.Note = "未配置"
			out = append(out, a)
			continue
		}
		// ML 资产与引擎 mlFor 同源解析：配置值只是候选之一。只 stat 配置值
		// 会把「资产在安装目录、但进程 cwd 不在安装目录」误报成缺失（实测：
		// 仓库根启动 CLI serve 时诊断报 ml_assets 缺失，但同一进程的 ML
		// 先验/严重度预测实际正常）。
		probePath := it.path
		if it.name == "ML 模型资产" {
			if dir := ml.LocateAssetsDir(ml.AssetCandidates(cfg.ML.AssetsDir)...); dir != "" {
				probePath = dir
			}
		}
		st, err := os.Stat(probePath)
		if err != nil {
			out = append(out, a)
			continue
		}
		if it.dir {
			if st.IsDir() {
				a.Present = true
				a.Note = "" // 就位时不显示「缺失影响」文案
			}
			out = append(out, a)
			continue
		}
		if !st.IsDir() {
			a.Present = true
			a.SizeKB = st.Size() / 1024
			a.Note = "" // 就位时不显示「缺失影响」文案
		}
		out = append(out, a)
	}
	return out
}

// ConfigSummary 配置摘要（脱敏）。
//
// ⚠️ **绝不包含** API Token、登录凭证、Cookie 等秘密值——只暴露"是否已设置"
// （布尔）。路径只给文件名，不给绝对路径（避免泄漏本机目录结构）。
func ConfigSummary(cfg *config.Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}
	return map[string]any{
		"scan": map[string]any{
			"rate_interval_ms": cfg.Scan.RateIntervalMS,
			"timeout_sec":      cfg.Scan.TimeoutSec,
			"max_hops":         cfg.Scan.MaxHops,
			"max_body_mb":      cfg.Scan.MaxBodyMB,
			"deep":             cfg.Scan.Deep,
			"resolve":          cfg.Scan.Resolve,
			"max_concurrent":   cfg.Scan.MaxConcurrent,
			"max_memory_mb":    cfg.Scan.MaxMemoryMB,
			"graph":            cfg.Scan.Graph,
		},
		"target": map[string]any{
			"allow_private": cfg.Target.AllowPrivate,
		},
		"checks": map[string]any{
			"level":      cfg.Checks.Level,
			"nuclei_cap": cfg.Checks.NucleiCap,
			"workers":    cfg.Checks.Workers,
			"plugin_dir": maskPath(cfg.Checks.PluginDir),
		},
		"crawler": map[string]any{
			"max_pages":      cfg.Crawler.MaxPages,
			"respect_robots": cfg.Crawler.RespectRobots,
			"timeout_sec":    cfg.Crawler.TimeoutSec,
			"headless":       cfg.Crawler.Headless,
			"headless_all":   cfg.Crawler.HeadlessAllPages,
		},
		"dast": map[string]any{
			"max_params":   cfg.DAST.MaxParams,
			"time_blind":   cfg.DAST.TimeBlind,
			"bool_blind":   cfg.DAST.BoolBlind,
			"deep_probes":  cfg.DAST.DeepProbes,
			"error_status": cfg.DAST.ErrorStatus,
		},
		"intel": map[string]any{
			"search_limit": cfg.Intel.SearchLimit,
			"update_hours": cfg.Intel.UpdateHours,
		},
		"netsec": map[string]any{
			"mail_check": cfg.Netsec.MailCheck,
		},
		"web": map[string]any{
			"listen":        cfg.Web.Listen,
			"api_token_set": cfg.Web.APIToken != "",
		},
		"store": map[string]any{
			"data_dir":    maskPath(cfg.Store.DataDir),
			"max_records": cfg.Store.MaxRecords,
		},
		"auth": map[string]any{
			"enabled":      cfg.Auth.LoginURL != "",
			"username_set": cfg.Auth.Username != "",
			"password_set": cfg.Auth.Password != "",
		},
		"oob": map[string]any{
			"enabled": cfg.Oob.Enabled,
			"mode":    cfg.Oob.Mode,
		},
		"exploit": map[string]any{
			"enabled": cfg.Exploit.Enabled,
		},
		"ml": map[string]any{
			"predict":    cfg.ML.Predict,
			"sev_onnx":   cfg.ML.SevONNX,
			"assets_dir": maskPath(cfg.ML.AssetsDir),
		},
		"feedback": map[string]any{
			"endpoint_set": cfg.Feedback.Endpoint != "",
		},
	}
}

// maskPath 只保留路径的最后一段（文件名/目录名），不暴露本机目录结构。
//
// 不用 filepath.Base：平台相关的分隔符语义会把另一种分隔符当普通字符——
// 在 Linux 上 filepath.Base(`C:\Users\x\state`) 会原样返回整串，等于没脱敏
// （诊断包完全可能在 Windows 采集、Linux 复制分析，或反之）。这里同时认
// `/` 与 `\`，两种形态都只保留最后一段。
func maskPath(p string) string {
	if p == "" {
		return ""
	}
	trimmed := strings.TrimRight(p, `/\`)
	if trimmed == "" {
		return ""
	}
	if i := strings.LastIndexAny(trimmed, `/\`); i >= 0 {
		return trimmed[i+1:]
	}
	return trimmed
}

// renderText 渲染成可直接粘贴到 Issue 的纯文本。
func (r *Report) renderText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SiteLens 诊断包\n")
	fmt.Fprintf(&b, "生成时间：%s\n", r.GeneratedAt)
	fmt.Fprintf(&b, "引擎版本：%s\n", r.Version)
	fmt.Fprintf(&b, "平台：%s（%s，%s 核）\n", r.Platform, r.Runtime["go_version"], r.Runtime["num_cpu"])
	fmt.Fprintf(&b, "\n[数据资产就位情况]\n")
	for _, a := range r.Assets {
		state := "缺失"
		if a.Present {
			state = fmt.Sprintf("就位（%d KB）", a.SizeKB)
		}
		fmt.Fprintf(&b, "  - %s：%s\n", a.Name, state)
	}
	if len(r.Degraded) > 0 {
		fmt.Fprintf(&b, "\n[当前降级的能力]\n")
		for _, d := range r.Degraded {
			fmt.Fprintf(&b, "  - %s\n", d)
		}
	}
	if len(r.RecentErrors) > 0 {
		fmt.Fprintf(&b, "\n[最近的失败记录]\n")
		for _, e := range r.RecentErrors {
			fmt.Fprintf(&b, "  - %s\n", e)
		}
	}
	fmt.Fprintf(&b, "\n[配置摘要]\n")
	fmt.Fprintf(&b, "%s\n", prettyJSON(r.Config))
	return b.String()
}

// prettyJSON 轻量 JSON 缩进（避免为一个摘要引入额外依赖）。
func prettyJSON(v any) string {
	var b strings.Builder
	writeJSON(&b, v, 0)
	return b.String()
}

func writeJSON(b *strings.Builder, v any, depth int) {
	pad := strings.Repeat("  ", depth)
	pad2 := strings.Repeat("  ", depth+1)
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range keys {
			b.WriteString(pad2)
			b.WriteString(k)
			b.WriteString(": ")
			writeJSON(b, t[k], depth+1)
			if i < len(keys)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(pad + "}")
	case []string:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[")
		for i, s := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(s)
		}
		b.WriteString("]")
	default:
		fmt.Fprintf(b, "%v", v)
	}
}
