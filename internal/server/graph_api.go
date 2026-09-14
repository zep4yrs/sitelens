// 结构化事实图的 API（4.0 P8）。
//
// 路由：
//
//	GET /api/graph/{id}          图摘要 + 实体计数 + 链视图数据（JSON）
//	GET /api/graph/{id}/jsonl    原始 graph JSONL（下载 / 供 5.0 读取）
//	GET /api/graph/{id}/chain    攻击链视图数据（节点/边，带类型与标签）
//
// 设计：图存于 store 的独立文件（见 internal/store/graph.go），本层只读。
// 404 明确区分「无该扫描」与「该扫描未收集图」；损坏图返回 500 且说明是损坏
// 而非不存在（不把损坏伪装成缺失）。
package server

import (
	"net/http"
	"strconv"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// hGraph 图摘要 + 全量实体（供前端链视图/实体表）。
func (s *Server) hGraph(w http.ResponseWriter, r *http.Request) {
	id, ok := s.graphID(w, r)
	if !ok {
		return
	}
	if s.st.Get(id) == nil {
		writeJSON(w, 404, map[string]any{"error": "记录不存在"})
		return
	}
	g, status := s.st.GraphWithStatus(id)
	switch status {
	case "absent":
		writeJSON(w, 404, map[string]any{"error": "该扫描未收集结构化事实图", "scan_id": id})
		return
	case "corrupt":
		writeJSON(w, 500, map[string]any{"error": "图数据损坏（无法解析）", "scan_id": id})
		return
	}
	m, _ := s.st.GraphManifestOf(id)
	out := map[string]any{
		"scan_id": id, "schema": g.Schema, "counts": g.Counts(),
	}
	if m != nil {
		out["manifest"] = m.Summary()
	}
	// 实体全量（前端按需渲染；图规模有限，直接返回 JSON 即可）。
	out["entry_points"] = g.EntryPoints
	out["vuln_nodes"] = g.VulnNodes
	out["dataflows"] = g.Dataflows
	out["cwe_rels"] = g.CWERels
	out["impacts"] = g.Impacts
	out["priv_changes"] = g.PrivChanges
	out["evidence_links"] = g.EvidenceLinks
	writeJSON(w, 200, out)
}

// hGraphJSONL 原始 JSONL 下载（schema 版本化格式，5.0 ML 直接读取）。
func (s *Server) hGraphJSONL(w http.ResponseWriter, r *http.Request) {
	id, ok := s.graphID(w, r)
	if !ok {
		return
	}
	data, found := s.st.GraphJSONL(id)
	if !found {
		if s.st.Get(id) == nil {
			writeJSON(w, 404, map[string]any{"error": "记录不存在"})
			return
		}
		writeJSON(w, 404, map[string]any{"error": "该扫描未收集结构化事实图"})
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition",
		"attachment; filename=\"sitelens-graph-"+strconv.FormatInt(id, 10)+".jsonl\"")
	_, _ = w.Write(data)
}

// hGraphChain 攻击链视图数据（节点 + 边 + 统计）。
func (s *Server) hGraphChain(w http.ResponseWriter, r *http.Request) {
	id, ok := s.graphID(w, r)
	if !ok {
		return
	}
	g, status := s.st.GraphWithStatus(id)
	switch status {
	case "absent":
		writeJSON(w, 404, map[string]any{"error": "该扫描未收集结构化事实图", "scan_id": id})
		return
	case "corrupt":
		writeJSON(w, 500, map[string]any{"error": "图数据损坏", "scan_id": id})
		return
	}
	// 边按类型统计（前端图例用）。
	byKind := map[string]int{}
	for _, e := range g.ChainEdges {
		byKind[e.Kind]++
	}
	// 每个链节点补出「引用实体的可读标签」，便于前端直接展示。
	labels := chainNodeLabels(g)
	nodes := make([]map[string]any, 0, len(g.ChainNodes))
	for _, n := range g.ChainNodes {
		nodes = append(nodes, map[string]any{
			"id": n.ID, "kind": n.Kind, "ref_id": n.RefID,
			"label": n.Label, "resolved": labels[n.RefID],
			"evidence_count": len(n.EvidenceIDs),
		})
	}
	writeJSON(w, 200, map[string]any{
		"scan_id": id, "schema": g.Schema,
		"nodes": nodes, "edges": nonNilEdges(g.ChainEdges),
		"edge_kinds": byKind,
		"node_count": len(g.ChainNodes), "edge_count": len(g.ChainEdges),
		"skipped_hint": "无真实证据的候选边不会被建立（见 chain.Build）",
	})
}

// nonNilEdges 保证边列表在 JSON 里是数组而非 null（前端无需判空）。
func nonNilEdges(edges []model.ChainEdge) []model.ChainEdge {
	if edges == nil {
		return []model.ChainEdge{}
	}
	return edges
}

// graphID 解析路径 id（统一错误响应）。
func (s *Server) graphID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "id 非法"})
		return 0, false
	}
	return id, true
}

// chainNodeLabels 为链节点的引用实体生成可读标签（ref_id → 文本）。
func chainNodeLabels(g *model.ScanGraph) map[string]string {
	out := map[string]string{}
	for _, v := range g.VulnNodes {
		label := v.Title
		if label == "" {
			label = v.CheckID
		}
		if label == "" {
			label = v.RuleID
		}
		if label == "" {
			label = v.ID
		}
		if v.URL != "" {
			label += " @ " + v.URL
		}
		out[v.ID] = label
	}
	for _, ep := range g.EntryPoints {
		out[ep.ID] = ep.URL
	}
	for _, d := range g.Dataflows {
		label := d.File
		if d.Func != "" {
			label += " · " + d.Func
		}
		if d.Sink != nil && d.Sink.Line > 0 {
			label += ":" + strconv.Itoa(d.Sink.Line)
		}
		out[d.ID] = label
	}
	for _, im := range g.Impacts {
		out[im.ID] = "影响：" + im.Kind
	}
	for _, p := range g.PrivChanges {
		out[p.ID] = "权限变化：" + p.Mechanism
	}
	return out
}
