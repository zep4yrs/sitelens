package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
)

// preflightTTL 预检结果缓存时效（与 engine.PreflightTTL 对齐）。
const preflightTTL = 120 * time.Second

// preflightDedupe 同一 URL 在此窗口内重复请求直接复用（避免用户反复改参数触发重复预检）。
const preflightDedupe = 30 * time.Second

// preflightCache 进程内预检缓存：按 id 与归一化 URL 双索引，TTL + 上限防内存膨胀。
type preflightCache struct {
	mu    sync.Mutex
	byID  map[string]*preflightEntry
	byURL map[string]*preflightEntry
	ttl   time.Duration
	max   int
}

type preflightEntry struct {
	id string
	pf *engine.Preflight
	at time.Time
}

func newPreflightCache() *preflightCache {
	return &preflightCache{
		byID:  map[string]*preflightEntry{},
		byURL: map[string]*preflightEntry{},
		ttl:   preflightTTL,
		max:   32,
	}
}

func (c *preflightCache) gcLocked(now time.Time) {
	for id, e := range c.byID {
		if now.Sub(e.at) > c.ttl {
			delete(c.byID, id)
			if cur, ok := c.byURL[engine.NormalizePreflightURL(e.pf.RequestedURL)]; ok && cur.id == id {
				delete(c.byURL, engine.NormalizePreflightURL(e.pf.RequestedURL))
			}
		}
	}
}

// get 按 id 取未过期的预检结果。
func (c *preflightCache) get(id string) *engine.Preflight {
	if id == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.gcLocked(now)
	e := c.byID[id]
	if e == nil || now.Sub(e.at) > c.ttl {
		return nil
	}
	return e.pf
}

// recent 按归一化 URL 取最近一次预检（maxAge 内），返回 id 与结果。
func (c *preflightCache) recent(norm string, maxAge time.Duration) (string, *engine.Preflight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.gcLocked(now)
	e := c.byURL[norm]
	if e == nil || now.Sub(e.at) > maxAge || now.Sub(e.at) > c.ttl {
		return "", nil
	}
	return e.id, e.pf
}

// put 写入缓存并返回预检 id；超过上限时淘汰最旧条目。
func (c *preflightCache) put(norm string, pf *engine.Preflight) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.gcLocked(now)
	// 上限：删最旧
	for len(c.byID) >= c.max {
		var oldestID string
		var oldest time.Time
		for id, e := range c.byID {
			if oldestID == "" || e.at.Before(oldest) {
				oldestID, oldest = id, e.at
			}
		}
		if oldestID == "" {
			break
		}
		if e := c.byID[oldestID]; e != nil {
			delete(c.byURL, engine.NormalizePreflightURL(e.pf.RequestedURL))
		}
		delete(c.byID, oldestID)
	}
	id := "pf_" + newID()
	e := &preflightEntry{id: id, pf: pf, at: now}
	c.byID[id] = e
	c.byURL[norm] = e
	return id
}

// preflightResp 预检响应：preflight_id + 引擎预检字段（扁平）。
type preflightResp struct {
	ID string `json:"preflight_id"`
	*engine.Preflight
}

// hPreflight 扫描前只读预检：1 次 GET（≤ MaxHops 跳），结果缓存供建议卡展示
// 与 /api/scan 首页复用。受 scan.preflight 总闸控制。
func (s *Server) hPreflight(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	if !cfg.Scan.Preflight {
		writeJSON(w, 400, map[string]any{"error": "预检已关闭（scan.preflight: false）"})
		return
	}
	var body struct {
		URL        string `json:"url"`
		BrowserUA  bool   `json:"browser_ua"`
		AuthCookie string `json:"auth_cookie"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	urlStr := strings.TrimSpace(body.URL)
	if urlStr == "" {
		writeJSON(w, 400, map[string]any{"error": "url 不能为空"})
		return
	}
	norm := engine.NormalizePreflightURL(urlStr)
	if id, pf := s.preflights.recent(norm, preflightDedupe); pf != nil {
		writeJSON(w, 200, preflightResp{ID: id, Preflight: pf})
		return
	}
	pf, err := s.eng.Preflight(urlStr, engine.Options{BrowserUA: body.BrowserUA, AuthCookie: body.AuthCookie})
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	id := s.preflights.put(norm, pf)
	writeJSON(w, 200, preflightResp{ID: id, Preflight: pf})
}
