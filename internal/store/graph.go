// 结构化事实图的持久化（4.0 P8）。
//
// 设计：图**不写进 history.json**——扫描记录（ScanRecord）仍按 3.0 形态存
// 单文件，图另存 `data/state/graph/<scan_id>/graph.jsonl` + `manifest.json`。
// 理由：图比扫描摘要大得多（证据正文/实体），内嵌会让 history.json 迅速膨胀，
// 且破坏「history.json 格式与语义不动」的 3.0 兼容承诺。
//
// 目录结构（每个 scan_id 一个目录，便于整体删除与人工查看）：
//
//	data/state/graph/<id>/
//	  ├── graph.jsonl   实体行（schema 头 + 每实体一行；见 internal/model）
//	  └── manifest.json 元信息（schema/counts/generated_at/saved_at）
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// GraphManifest 图清单（便于不带 JSONL 解析就得知规模）。
type GraphManifest struct {
	Schema      string         `json:"schema"`
	ScanID      int64          `json:"scan_id"`
	ScanURL     string         `json:"scan_url,omitempty"`
	GeneratedAt string         `json:"generated_at,omitempty"`
	SavedAt     string         `json:"saved_at"`
	Counts      map[string]int `json:"counts"`
	Entities    int            `json:"entities"`
}

// graphDir 某个扫描的图目录。
func (s *Store) graphDir(id int64) string {
	return filepath.Join(s.dataDir, "graph", strconv.FormatInt(id, 10))
}

// saveGraph 把图写入 graph/<id>/（JSONL + manifest）。调用方须持锁。
// 失败不阻塞扫描主流程（返回 error 供上层决定是否记日志）。
func (s *Store) saveGraph(id int64, g *model.ScanGraph, scanURL string) error {
	if g == nil {
		return nil
	}
	dir := s.graphDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := g.MarshalJSONL()
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "graph.jsonl.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "graph.jsonl")); err != nil {
		return err
	}
	m := GraphManifest{
		Schema: g.Schema, ScanID: id, ScanURL: scanURL,
		GeneratedAt: g.GeneratedAt, SavedAt: time.Now().Format("2006-01-02 15:04:05"),
		Counts: g.Counts(),
	}
	for _, n := range m.Counts {
		m.Entities += n
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), mb, 0o644)
}

// Graph 读取某次扫描的图（不存在返回 nil,false）。损坏文件返回 status="corrupt"。
func (s *Store) Graph(id int64) (*model.ScanGraph, bool) {
	g, status := s.GraphWithStatus(id)
	return g, status == "ok"
}

// GraphWithStatus 读取图并给出状态：ok | absent | corrupt。
// 便于 API 区分「没有图」与「图坏了」（不把损坏伪装成不存在）。
func (s *Store) GraphWithStatus(id int64) (*model.ScanGraph, string) {
	path := filepath.Join(s.graphDir(id), "graph.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, "absent"
	}
	defer f.Close()
	g, err := model.ReadJSONL(f)
	if err != nil {
		return nil, "corrupt"
	}
	return g, "ok"
}

// GraphJSONL 返回图的原始 JSONL 字节（导出用）。
func (s *Store) GraphJSONL(id int64) ([]byte, bool) {
	data, err := os.ReadFile(filepath.Join(s.graphDir(id), "graph.jsonl"))
	if err != nil {
		return nil, false
	}
	return data, true
}

// GraphManifestOf 读 manifest（不存在返回 nil,false）。
func (s *Store) GraphManifestOf(id int64) (*GraphManifest, bool) {
	data, err := os.ReadFile(filepath.Join(s.graphDir(id), "manifest.json"))
	if err != nil {
		return nil, false
	}
	var m GraphManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return &m, true
}

// HasGraph 报告某次扫描是否存有图。
func (s *Store) HasGraph(id int64) bool {
	_, err := os.Stat(filepath.Join(s.graphDir(id), "graph.jsonl"))
	return err == nil
}

// GraphIDs 返回所有存有图的 scan_id（升序）。
func (s *Store) GraphIDs() []int64 {
	entries, err := os.ReadDir(filepath.Join(s.dataDir, "graph"))
	if err != nil {
		return nil
	}
	var out []int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, err := strconv.ParseInt(e.Name(), 10, 64)
		if err != nil {
			continue
		}
		if s.HasGraph(id) {
			out = append(out, id)
		}
	}
	return out
}

// deleteGraph 删除某次扫描的图目录（幂等）。
func (s *Store) deleteGraph(id int64) {
	_ = os.RemoveAll(s.graphDir(id))
}

// Summary 供 API 输出的紧凑摘要。
func (m *GraphManifest) Summary() map[string]any {
	return map[string]any{
		"schema": m.Schema, "scan_id": m.ScanID, "scan_url": m.ScanURL,
		"generated_at": m.GeneratedAt, "saved_at": m.SavedAt,
		"counts": m.Counts, "entities": m.Entities,
	}
}
