// 设置页后端：配置读取/保存（写回用户 yml，Node 方式保留注释与
// 未纳管键）+ OSV 同步触发与状态。
//
// 生效语义（诚实契约，UI 明示）：
//   - 保存后写回 .sitelens.yml（Node 读改写，尽量保留注释）
//   - 扫描类键（rate/timeout/max_pages/respect_robots/nuclei_cap）对
//     下一次扫描热生效
//   - 监听地址需重启服务；API Token 立即生效
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// defaultOverridesName overrides_path 缺省文件名（相对数据目录）。
const defaultOverridesName = "intel_overrides.json"

// apiTokenMask GET /api/settings 回显 api_token 时的掩码（V-11）。
// 不是可用 token：PUT 收到该值时按"不修改"处理（hSettingsPut）。
const apiTokenMask = "sk-****"

// resolveOverridesPath 校验并归一设置页提交的 overrides_path。
//
// 安全约束（BUG-006）：该键运行期会被 OSV 同步写盘
// （POST /api/osv-sync → intel.SaveOverrides），此前 PUT /api/settings
// 零校验 → 可把落盘点改到任意路径（含重启后仍生效）。现限定在固定
// 数据目录 cfg.Store.DataDir 内：
//   - 空值 → 数据目录下的默认文件；
//   - 相对路径 → 相对数据目录解析（归一为绝对路径）；
//   - 绝对路径 → 允许，但必须位于数据目录内；
//   - 越界（.. 穿越 / 其它目录或盘符）→ 返回错误，调用方回 400。
//
// 判定用 filepath.Rel 而非字符串前缀：Windows 下卷标大小写与 / \ 分隔符
// 差异都会让 HasPrefix 误判（C:\Data 与 c:/data 应视为同一目录）。
func resolveOverridesPath(dataDir, raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return filepath.Join(dataDir, defaultOverridesName), nil
	}
	absDir, err := filepath.Abs(dataDir)
	if err != nil {
		return "", fmt.Errorf("数据目录不可解析：%w", err)
	}
	p := strings.TrimSpace(raw)
	if !filepath.IsAbs(p) {
		p = filepath.Join(absDir, p)
	}
	absPath, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("路径不可解析：%w", err)
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("必须位于数据目录内（%s）", absDir)
	}
	return absPath, nil
}

// settingsConfig 设置页可读写的配置投影（只含允许远程修改的键）。
//
// APIToken 用指针表达"字段是否出现"（D-04 契约）：
//   - nil（请求体里没有该字段）→ 不修改当前 token；
//   - 指向 ""（显式传空串）→ 清除 token（= 关闭 X-Token 鉴权）；
//   - 指向非空字符串 → 覆盖为新 token。
//
// 注意：不能用 string 的零值判断——旧前端在"没动 token 输入框"时也会传空串，
// 那会把已配置的 token 清掉（用户从有鉴权变成无鉴权）。
type settingsConfig struct {
	Web struct {
		Listen   string  `json:"listen"`
		APIToken *string `json:"api_token,omitempty"`
	} `json:"web"`
	Crawler struct {
		MaxPages        int  `json:"max_pages"`
		RespectRobots   bool `json:"respect_robots"`
		MaxLinksPerPage int  `json:"max_links_per_page"`
		TimeoutSec      int  `json:"timeout_sec"`
	} `json:"crawler"`
	Scan struct {
		RateIntervalMS int `json:"rate_interval_ms"`
		TimeoutSec     int `json:"timeout_sec"`
	} `json:"scan"`
	Checks struct {
		NucleiCap int `json:"nuclei_cap"`
	} `json:"checks"`
	Exploit struct {
		Enabled bool `json:"enabled"` // 利用级验证总闸（对下次扫描热生效）
	} `json:"exploit"`
	Intel struct {
		OverridesPath string `json:"overrides_path"`
	} `json:"intel"`
	Batch struct {
		MaxURLs int `json:"max_urls"`
	} `json:"batch"`
	ML struct {
		Predict   bool `json:"predict"`    // AI 总闸：先验调度 + 预测富化
		SevLinear bool `json:"sev_linear"` // 线性严重度兜底（NVD 查表优先，5.2 默认开）
		SevONNX   bool `json:"sev_onnx"`   // ONNX 严重度（需可选高级包构建）
	} `json:"ml"`
}

func (s *Server) settingsCfg() settingsConfig {
	// A-09：读配置快照（无锁），一次调用内用同一份，避免字段来自不同版本。
	cfg := s.cfgSnap()
	var v settingsConfig
	if cfg != nil {
		v.Web.Listen = cfg.Web.Listen
		v.Crawler.MaxPages = cfg.Crawler.MaxPages
		v.Crawler.RespectRobots = cfg.Crawler.RespectRobots
		v.Crawler.MaxLinksPerPage = cfg.Crawler.MaxLinksPerPage
		v.Crawler.TimeoutSec = cfg.Crawler.TimeoutSec
		v.Scan.RateIntervalMS = cfg.Scan.RateIntervalMS
		v.Scan.TimeoutSec = cfg.Scan.TimeoutSec
		v.Checks.NucleiCap = cfg.Checks.NucleiCap
		v.Exploit.Enabled = cfg.Exploit.Enabled
		v.Intel.OverridesPath = cfg.Intel.OverridesPath
		v.Batch.MaxURLs = cfg.Batch.MaxURLs
		v.ML.Predict = cfg.ML.Predict
		v.ML.SevLinear = cfg.ML.SevLinear
		v.ML.SevONNX = cfg.ML.SevONNX
	}
	// 内部视图带真实 token（供 hSettingsGet 判 api_token_set 与日志）；
	// HTTP 响应里 hSettingsGet 会把它清成 nil（V-11 不回明文）。
	tok := s.token()
	v.Web.APIToken = &tok
	return v
}

// applySettings 把设置页提交的值写回内存（热生效：扫描/爬取/API token）。
//
// A-09 copy-on-write 语义：全程持 cfgMu（写侧串行化），先深拷贝当前快照、
// 只改拷贝、最后原子换枪并同步引擎快照；**绝不原地修改旧结构**。
// 生效边界：对下一次扫描/请求生效；进行中的扫描持旧快照不受影响。
func (s *Server) applySettings(v settingsConfig) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	old := s.cfgSnap()
	newCfg := cloneConfig(old)
	if newCfg == nil {
		newCfg = config.Default()
	}
	// D-04 契约：字段缺省 = 不修改；显式 "" = 清除；非空 = 覆盖。
	if v.Web.APIToken != nil {
		tok := *v.Web.APIToken
		newCfg.Web.APIToken = tok
		s.apiToken.Store(&tok) // 原子换枪：guard 读侧无锁
	}
	if v.Crawler.MaxPages > 0 {
		newCfg.Crawler.MaxPages = v.Crawler.MaxPages
	}
	newCfg.Crawler.RespectRobots = v.Crawler.RespectRobots
	if v.Crawler.MaxLinksPerPage > 0 {
		newCfg.Crawler.MaxLinksPerPage = v.Crawler.MaxLinksPerPage
	}
	if v.Crawler.TimeoutSec > 0 {
		newCfg.Crawler.TimeoutSec = v.Crawler.TimeoutSec
	}
	if v.Scan.RateIntervalMS >= 0 {
		newCfg.Scan.RateIntervalMS = v.Scan.RateIntervalMS
	}
	if v.Scan.TimeoutSec > 0 {
		newCfg.Scan.TimeoutSec = v.Scan.TimeoutSec
	}
	if v.Checks.NucleiCap > 0 {
		newCfg.Checks.NucleiCap = v.Checks.NucleiCap
	}
	newCfg.Exploit.Enabled = v.Exploit.Enabled
	newCfg.Intel.OverridesPath = v.Intel.OverridesPath
	if v.Batch.MaxURLs > 0 {
		newCfg.Batch.MaxURLs = v.Batch.MaxURLs
	}
	// ML 开关热生效：predict 引擎每次扫描现读；sev_onnx 翻转时作废
	// 打分器的一次性尝试缓存（下次扫描按新开关重建/跳过）
	if old != nil && old.ML.SevONNX != v.ML.SevONNX && s.eng != nil {
		s.eng.InvalidateMLSev()
	}
	// C2-10：AI 总闸由开转关时释放 ML 资产常驻（cve-tech 系数 94MB），
	// 下次重新开启扫描时按需重建。仅在"关"的瞬间释放，避免抖动反复读盘。
	if old != nil && old.ML.Predict && !v.ML.Predict && s.eng != nil {
		s.eng.InvalidateML()
	}
	newCfg.ML.Predict = v.ML.Predict
	newCfg.ML.SevLinear = v.ML.SevLinear
	newCfg.ML.SevONNX = v.ML.SevONNX

	// 原子换枪：此后新请求/新扫描读到新快照；旧快照（含进行中的扫描）
	// 保持不变，不会被后续写入污染。
	s.cfgPtr.Store(newCfg)
	if s.eng != nil {
		s.eng.SetConfig(newCfg)
	}
}

// persistSettings 把设置写回用户 yml（Node 读改写：保留注释与未纳管键）。
func (s *Server) persistSettings(v settingsConfig) error {
	data, err := os.ReadFile(s.cfgPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) == 0 {
		data = []byte("{}\n")
	}
	updates := map[string]map[string]any{
		"web": {"listen": v.Web.Listen},
		"crawler": {
			"max_pages":          v.Crawler.MaxPages,
			"respect_robots":     v.Crawler.RespectRobots,
			"max_links_per_page": v.Crawler.MaxLinksPerPage,
			"timeout_sec":        v.Crawler.TimeoutSec,
		},
		"scan": {
			"rate_interval_ms": v.Scan.RateIntervalMS,
			"timeout_sec":      v.Scan.TimeoutSec,
		},
		"checks":  {"nuclei_cap": v.Checks.NucleiCap},
		"exploit": {"enabled": v.Exploit.Enabled},
		"intel":   {"overrides_path": v.Intel.OverridesPath},
		"batch":   {"max_urls": v.Batch.MaxURLs},
		"ml":      {"predict": v.ML.Predict, "sev_linear": v.ML.SevLinear, "sev_onnx": v.ML.SevONNX},
	}
	// D-04：字段缺省时不写 api_token 键（避免把 yml 里的明文 token 抹掉）；
	// 显式 "" 也要写（清除），非空则覆盖。
	if v.Web.APIToken != nil {
		updates["web"]["api_token"] = *v.Web.APIToken
	}
	out, err := config.UpsertYAMLSections(data, updates)
	if err != nil {
		return err
	}
	// 0644 → 0600（BUG-024）：新文件时配置里含 web.api_token 明文；
	// 落盘后显式 Chmod 也收紧历史遗留的 0644 文件（Windows 下仅只读位生效，
	// 属平台限制，代码仍按最小权限写）。
	if err := os.WriteFile(s.cfgPath, out, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(s.cfgPath, 0o600)
	return nil
}

func (s *Server) hSettingsGet(w http.ResponseWriter, r *http.Request) {
	c := s.settingsCfg()
	// V-11：绝不回显 api_token 明文（只读角色也能读本接口）。以
	// api_token_set 布尔为主判据（D-04/V-11 契约，F6 已按此实现），
	// 并从响应结构里摘掉 api_token 字段（nil + omitempty）。
	tokenSet := c.Web.APIToken != nil && strings.TrimSpace(*c.Web.APIToken) != ""
	c.Web.APIToken = nil
	resp := map[string]any{
		"web": c.Web, "crawler": c.Crawler, "scan": c.Scan, "checks": c.Checks,
		"exploit": c.Exploit, "intel": c.Intel, "batch": c.Batch, "ml": c.ML,
		"api_token_set": tokenSet,
		"note":          "保存后：扫描/爬取/Token 立即生效；监听地址需重启服务",
	}
	// config_path 含主机用户名/目录结构，仅 admin（none 模式按本机单用户处理）可见。
	if isAdminRequest(r) && s.cfgPath != "" {
		resp["config_path"] = s.cfgPath
	}
	writeJSON(w, 200, resp)
}

func (s *Server) hSettingsPut(w http.ResponseWriter, r *http.Request) {
	// V-21：设置体正常只有几百字节；64KB 硬上限防超大 JSON 占内存/CPU
	// （其余端点普遍 io.LimitReader 1MB，本端点此前完全无限制）。
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var v settingsConfig
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeJSON(w, 400, map[string]any{"error": "JSON 解析失败（请求体需 ≤64KB）"})
		return
	}
	// D-04 契约：api_token 字段"缺省 = 不修改 / 显式 "" = 清除 / 非空 = 覆盖"。
	// 兼容旧前端把掩码原样回传的情况：掩码视为"不修改"。
	if v.Web.APIToken != nil && *v.Web.APIToken == apiTokenMask {
		v.Web.APIToken = nil
	}
	if v.Web.Listen == "" || v.Crawler.MaxPages <= 0 {
		writeJSON(w, 400, map[string]any{"error": "listen 与 max_pages 必填"})
		return
	}
	// BUG-006：overrides_path 会被 OSV 同步当落盘路径使用，必须限定在
	// 数据目录内；非法值整单拒绝（不落 yml、不改内存），避免"写盘路径
	// 已生效但配置没保存"的半生效状态。
	// A-09：配置读快照（无锁）。overrides_path 的合法根目录取当前快照。
	cfgSnap := s.cfgSnap()
	if cfgSnap == nil {
		writeJSON(w, 500, map[string]any{"error": "配置未初始化"})
		return
	}
	ovPath, err := resolveOverridesPath(cfgSnap.Store.DataDir, v.Intel.OverridesPath)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "overrides_path 非法：" + err.Error()})
		return
	}
	v.Intel.OverridesPath = ovPath
	if err := s.persistSettings(v); err != nil {
		writeJSON(w, 500, map[string]any{"error": "写回失败：" + err.Error()})
		return
	}
	s.applySettings(v)
	resp := map[string]any{"ok": true,
		"note": "已保存：扫描/爬取/Token 立即生效；监听地址需重启服务"}
	// 显式清空 token 是安全姿态变化（/api/* 立刻变成无鉴权），必须回执提示。
	if v.Web.APIToken != nil && *v.Web.APIToken == "" {
		resp["token_cleared"] = true
		resp["api_token_set"] = false
		resp["note"] = "已保存：API Token 已清除（当前 /api/* 无鉴权，仅建议本机使用）"
	} else if v.Web.APIToken != nil {
		resp["api_token_set"] = true
	}
	writeJSON(w, 200, resp)
}

// ---- OSV 同步 ----

func (s *Server) hOsvSync(w http.ResponseWriter, r *http.Request) {
	s.osvMu.Lock()
	if s.osvRunning {
		s.osvMu.Unlock()
		writeJSON(w, 409, map[string]any{"error": "同步已在进行中"})
		return
	}
	s.osvRunning = true
	s.osvLastTime = time.Now().Format("2006-01-02 15:04:05")
	s.osvMu.Unlock()

	go func() {
		defer func() {
			s.osvMu.Lock()
			s.osvRunning = false
			s.osvMu.Unlock()
		}()
		// V-09：后台 goroutine panic 会终止整个进程（net/http 只 recover
		// 处理请求的那个 goroutine）。情报同步涉及大 JSON 解码，必须兜住。
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[panic] OSV 同步已恢复：%v\n%s", rec, debug.Stack())
				s.osvMu.Lock()
				s.osvLastMsg = "内部错误（已恢复）"
				s.osvMu.Unlock()
			}
		}()
		kb := s.KB()
		if kb == nil {
			s.osvMu.Lock()
			s.osvLastMsg = "知识库未加载"
			s.osvMu.Unlock()
			return
		}
		// A-09：落盘路径取同步开始时的配置快照（后台 goroutine 不裸读配置）。
		cfgSnap := s.cfgSnap()
		if cfgSnap == nil {
			s.osvMu.Lock()
			s.osvLastMsg = "配置未初始化"
			s.osvMu.Unlock()
			return
		}
		cves := kb.CollectCVEs()
		s.osvMu.Lock()
		s.osvTotal = len(cves)
		s.osvMu.Unlock()
		ov := intel.OsvSyncCollect(cves, 8)
		if err := intel.SaveOverrides(cfgSnap.Intel.OverridesPath, ov); err != nil {
			s.osvMu.Lock()
			s.osvLastMsg = "写入失败：" + err.Error()
			s.osvMu.Unlock()
			return
		}
		kb.ApplyOverrides(ov)
		s.osvMu.Lock()
		s.osvLastMsg = "同步完成"
		s.osvLastN = len(ov)
		s.osvMu.Unlock()
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "note": "同步已启动"})
}

func (s *Server) hOsvStatus(w http.ResponseWriter, r *http.Request) {
	s.osvMu.Lock()
	defer s.osvMu.Unlock()
	writeJSON(w, 200, map[string]any{
		"running":  s.osvRunning,
		"last_at":  s.osvLastTime,
		"last_msg": s.osvLastMsg,
		"last_n":   s.osvLastN,
	})
}
