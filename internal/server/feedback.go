package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/diag"
)

// 反馈与诊断（5.2）。
//
// 产品承诺「无埋点、无遥测、无崩溃上报」——《用户服务协议》原文。故这里的
// 形态是**本地生成 + 用户主动提交**：
//
//	GET  /api/diagnostics → 本机生成脱敏诊断包（不外发）
//	POST /api/feedback     → 把用户已确认的文本转发到**用户自建**的端点
//
// 本项目不提供、也不运营任何收集服务端——不存在"数据发到开发者服务器"。

// hDiagnostics 生成本机脱敏诊断包。
//
// 返回：结构化 JSON + 可直接粘贴的纯文本（text 字段）。
func (s *Server) hDiagnostics(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.Lock()
	cfg := s.cfg
	s.cfgMu.Unlock()
	writeJSON(w, 200, diag.Build(Version, cfg, s.recentScanErrors()))
}

// hFeedback 转发用户已确认的诊断包到**用户自建**的收集端点。
//
// body: {"text": "..."} —— 内容由前端拼好（用户可删减），后端**不加工、
// 不补内容**，保证「用户看到什么就发什么」。
//
// 未配置 feedback.endpoint 时返回明确提示（不是静默失败）：此时唯一路径是
// 「复制诊断包到 Issue」。
func (s *Server) hFeedback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求体解析失败"})
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeJSON(w, 400, map[string]any{"error": "诊断包内容为空"})
		return
	}

	s.cfgMu.Lock()
	endpoint := strings.TrimSpace(s.cfg.Feedback.Endpoint)
	timeout := s.cfg.Feedback.Timeout
	s.cfgMu.Unlock()

	if endpoint == "" {
		writeJSON(w, 200, map[string]any{
			"submitted": false,
			"message":   "未配置反馈提交地址（feedback.endpoint）。请复制诊断包到 Issue 反馈渠道。",
		})
		return
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		writeJSON(w, 400, map[string]any{"error": "feedback.endpoint 必须是 http/https 地址"})
		return
	}
	if timeout <= 0 {
		timeout = 15
	}
	payload, _ := json.Marshal(map[string]any{
		"text":    text,
		"version": Version,
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	})
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Post(endpoint, "application/json; charset=utf-8", bytes.NewReader(payload))
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "提交失败：" + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, 502, map[string]any{"error": "收集端点返回 HTTP " + strconv.Itoa(resp.StatusCode)})
		return
	}
	writeJSON(w, 200, map[string]any{"submitted": true, "message": "已提交到自建端点 " + endpoint})
}

// recentScanErrors 取扫描历史里最近的失败记录（脱敏：URL 去 userinfo）。
//
// 这回答的是用户最常问的「上次为什么失败」——比让用户贴整份日志有用得多。
func (s *Server) recentScanErrors() []string {
	if s.st == nil {
		return nil
	}
	var out []string
	for _, sum := range s.st.List(20, "") {
		rec := s.st.Get(sum.ID)
		if rec == nil || rec.Result == nil || rec.Result.Error == "" {
			continue
		}
		msg := rec.Result.Error
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		out = append(out, rec.ScannedAt+"  "+maskUserinfo(rec.URL)+"  →  "+msg)
		if len(out) >= 10 {
			break
		}
	}
	return out
}

// maskUserinfo 去掉 URL 里的 user:pass@（可能含凭据）。
func maskUserinfo(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("***")
	return u.String()
}
