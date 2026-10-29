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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// defaultOverridesName overrides_path 缺省文件名（相对数据目录）。
const defaultOverridesName = "intel_overrides.json"

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
type settingsConfig struct {
	Web struct {
		Listen   string `json:"listen"`
		APIToken string `json:"api_token"`
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
		Predict bool `json:"predict"`  // AI 总闸：先验调度 + 预测富化
		SevONNX bool `json:"sev_onnx"` // 严重度模型推理（需 onnx 构建）
	} `json:"ml"`
}

func (s *Server) settingsCfg() settingsConfig {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	var v settingsConfig
	v.Web.Listen = s.cfg.Web.Listen
	v.Web.APIToken = s.token()
	v.Crawler.MaxPages = s.cfg.Crawler.MaxPages
	v.Crawler.RespectRobots = s.cfg.Crawler.RespectRobots
	v.Crawler.MaxLinksPerPage = s.cfg.Crawler.MaxLinksPerPage
	v.Crawler.TimeoutSec = s.cfg.Crawler.TimeoutSec
	v.Scan.RateIntervalMS = s.cfg.Scan.RateIntervalMS
	v.Scan.TimeoutSec = s.cfg.Scan.TimeoutSec
	v.Checks.NucleiCap = s.cfg.Checks.NucleiCap
	v.Exploit.Enabled = s.cfg.Exploit.Enabled
	v.Intel.OverridesPath = s.cfg.Intel.OverridesPath
	v.Batch.MaxURLs = s.cfg.Batch.MaxURLs
	v.ML.Predict = s.cfg.ML.Predict
	v.ML.SevONNX = s.cfg.ML.SevONNX
	return v
}

// applySettings 把设置页提交的值写回内存（热生效：扫描/爬取/API token）。
func (s *Server) applySettings(v settingsConfig) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.cfg.Web.APIToken = v.Web.APIToken
	tok := v.Web.APIToken
	s.apiToken.Store(&tok) // 原子换枪：guard 读侧无锁
	if v.Crawler.MaxPages > 0 {
		s.cfg.Crawler.MaxPages = v.Crawler.MaxPages
	}
	s.cfg.Crawler.RespectRobots = v.Crawler.RespectRobots
	if v.Crawler.MaxLinksPerPage > 0 {
		s.cfg.Crawler.MaxLinksPerPage = v.Crawler.MaxLinksPerPage
	}
	if v.Crawler.TimeoutSec > 0 {
		s.cfg.Crawler.TimeoutSec = v.Crawler.TimeoutSec
	}
	if v.Scan.RateIntervalMS >= 0 {
		s.cfg.Scan.RateIntervalMS = v.Scan.RateIntervalMS
	}
	if v.Scan.TimeoutSec > 0 {
		s.cfg.Scan.TimeoutSec = v.Scan.TimeoutSec
	}
	if v.Checks.NucleiCap > 0 {
		s.cfg.Checks.NucleiCap = v.Checks.NucleiCap
	}
	s.cfg.Exploit.Enabled = v.Exploit.Enabled
	s.cfg.Intel.OverridesPath = v.Intel.OverridesPath
	if v.Batch.MaxURLs > 0 {
		s.cfg.Batch.MaxURLs = v.Batch.MaxURLs
	}
	// ML 开关热生效：predict 引擎每次扫描现读；sev_onnx 翻转时作废
	// 打分器的一次性尝试缓存（下次扫描按新开关重建/跳过）
	if s.cfg.ML.SevONNX != v.ML.SevONNX {
		s.eng.InvalidateMLSev()
	}
	s.cfg.ML.Predict = v.ML.Predict
	s.cfg.ML.SevONNX = v.ML.SevONNX
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
		"ml":      {"predict": v.ML.Predict, "sev_onnx": v.ML.SevONNX},
	}
	if v.Web.APIToken != "" {
		updates["web"]["api_token"] = v.Web.APIToken
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
	writeJSON(w, 200, map[string]any{
		"config":      s.settingsCfg(),
		"config_path": s.cfgPath,
		"note":        "保存后：扫描/爬取/Token 立即生效；监听地址需重启服务",
	})
}

func (s *Server) hSettingsPut(w http.ResponseWriter, r *http.Request) {
	var v settingsConfig
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeJSON(w, 400, map[string]any{"error": "JSON 解析失败"})
		return
	}
	if v.Web.Listen == "" || v.Crawler.MaxPages <= 0 {
		writeJSON(w, 400, map[string]any{"error": "listen 与 max_pages 必填"})
		return
	}
	// BUG-006：overrides_path 会被 OSV 同步当落盘路径使用，必须限定在
	// 数据目录内；非法值整单拒绝（不落 yml、不改内存），避免"写盘路径
	// 已生效但配置没保存"的半生效状态。
	ovPath, err := resolveOverridesPath(s.cfg.Store.DataDir, v.Intel.OverridesPath)
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
	writeJSON(w, 200, map[string]any{"ok": true,
		"note": "已保存：扫描/爬取/Token 立即生效；监听地址需重启服务"})
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
		kb := s.KB()
		if kb == nil {
			s.osvMu.Lock()
			s.osvLastMsg = "知识库未加载"
			s.osvMu.Unlock()
			return
		}
		cves := kb.CollectCVEs()
		s.osvMu.Lock()
		s.osvTotal = len(cves)
		s.osvMu.Unlock()
		ov := intel.OsvSyncCollect(cves, 8)
		if err := intel.SaveOverrides(s.cfg.Intel.OverridesPath, ov); err != nil {
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
