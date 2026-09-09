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
	"net/http"
	"os"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

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
}

func (s *Server) settingsCfg() settingsConfig {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	var v settingsConfig
	v.Web.Listen = s.cfg.Web.Listen
	v.Web.APIToken = s.apiToken
	v.Crawler.MaxPages = s.cfg.Crawler.MaxPages
	v.Crawler.RespectRobots = s.cfg.Crawler.RespectRobots
	v.Crawler.MaxLinksPerPage = s.cfg.Crawler.MaxLinksPerPage
	v.Crawler.TimeoutSec = s.cfg.Crawler.TimeoutSec
	v.Scan.RateIntervalMS = s.cfg.Scan.RateIntervalMS
	v.Scan.TimeoutSec = s.cfg.Scan.TimeoutSec
	v.Checks.NucleiCap = s.cfg.Checks.NucleiCap
	return v
}

// applySettings 把设置页提交的值写回内存（热生效：扫描/爬取/API token）。
func (s *Server) applySettings(v settingsConfig) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.cfg.Web.APIToken = v.Web.APIToken
	s.apiToken = v.Web.APIToken
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
		"checks": {"nuclei_cap": v.Checks.NucleiCap},
	}
	if v.Web.APIToken != "" {
		updates["web"]["api_token"] = v.Web.APIToken
	}
	out, err := config.UpsertYAMLSections(data, updates)
	if err != nil {
		return err
	}
	return os.WriteFile(s.cfgPath, out, 0o644)
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
			s.osvLastMsg = "同步完成"
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
