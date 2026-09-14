package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/engine"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// sampleGraph 构造一张最小合法图（含证据 + 节点 + CWE + 链）。
func sampleGraph() *model.ScanGraph {
	g := model.NewGraph("")
	g.GeneratedAt = "2026-09-14 10:00:00"
	ev := model.NewEvidence("response", model.OriginBlackbox, "dast", "",
		"http://t/?id=1", "", 0, "sql syntax error")
	g.Add(ev)
	vn := model.NewVulnNode(model.OriginBlackbox, "sqli-error", "", "http://t/?id=1",
		"id", "", 0, model.ObsPositive, "proven", model.ConfConfirmed, []string{ev.ID})
	g.Add(vn)
	g.Add(model.NewCWERel(model.KindVulnNode, vn.ID, "CWE-89", "mapping",
		model.ConfProbable, []string{ev.ID}))
	cn1 := model.NewChainNode("entry", vn.ID, "入口", []string{ev.ID})
	cn2 := model.NewChainNode("exploit", vn.ID, "利用", []string{ev.ID})
	g.Add(cn1)
	g.Add(cn2)
	if e, err := model.NewChainEdge(cn1.ID, cn2.ID, "sequence", []string{ev.ID},
		model.ConfProbable); err == nil {
		g.Add(e)
	}
	return g
}

// TestSaveGraphDetaches：Save 时图被剥离出 history.json，另存独立文件。
func TestSaveGraphDetaches(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	res := &engine.Result{
		URL: "http://t/", Host: "t", ScannedAt: "2026-09-14 10:00:00",
		Graph: sampleGraph(),
	}
	id := st.Save(res, map[string]any{"graph": true})

	// 1) history.json 里不应含 graph（不膨胀）。
	raw, err := os.ReadFile(filepath.Join(dir, "history.json"))
	if err != nil {
		t.Fatal(err)
	}
	var box struct {
		Scans []struct {
			Result map[string]any `json:"result"`
		} `json:"scans"`
	}
	if err := json.Unmarshal(raw, &box); err != nil {
		t.Fatal(err)
	}
	if len(box.Scans) != 1 {
		t.Fatalf("应 1 条记录，实得 %d", len(box.Scans))
	}
	if _, has := box.Scans[0].Result["graph"]; has {
		t.Error("history.json 不应含 graph（应剥离另存）")
	}

	// 2) 调用方的 res 仍持有图（不被就地清空）。
	if res.Graph == nil {
		t.Error("Save 不应改动调用方的 res.Graph")
	}

	// 3) 独立文件存在且可读。
	if !st.HasGraph(id) {
		t.Fatal("应存在图文件")
	}
	g, ok := st.Graph(id)
	if !ok || g == nil {
		t.Fatal("应能读回图")
	}
	if len(g.CWERels) != 1 || len(g.ChainEdges) != 1 {
		t.Errorf("图内容不符：cwe=%d chain=%d", len(g.CWERels), len(g.ChainEdges))
	}
}

// TestGraphManifest：manifest 记录 schema 与计数。
func TestGraphManifest(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	id := st.Save(&engine.Result{URL: "http://t/", Graph: sampleGraph()}, nil)

	m, ok := st.GraphManifestOf(id)
	if !ok {
		t.Fatal("应有 manifest")
	}
	if m.Schema != model.SchemaVersion {
		t.Errorf("schema = %q", m.Schema)
	}
	if m.Counts[model.KindVulnNode] != 1 {
		t.Errorf("vuln_node 计数 = %d，期望 1", m.Counts[model.KindVulnNode])
	}
	if m.Counts[model.KindChainEdge] != 1 {
		t.Errorf("链边计数 = %d，期望 1", m.Counts[model.KindChainEdge])
	}
	if m.Entities == 0 {
		t.Error("实体总数应 > 0")
	}
	if s := m.Summary(); s["scan_id"] != id {
		t.Errorf("Summary scan_id = %v", s["scan_id"])
	}
}

// TestGraphAbsentStatus：未收集图 → absent（区分于损坏）。
func TestGraphAbsentStatus(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	id := st.Save(&engine.Result{URL: "http://t/"}, nil) // 无图
	if st.HasGraph(id) {
		t.Error("无图时 HasGraph 应为 false")
	}
	g, status := st.GraphWithStatus(id)
	if g != nil || status != "absent" {
		t.Errorf("应 absent，实得 status=%q g=%v", status, g)
	}
	if _, ok := st.GraphJSONL(id); ok {
		t.Error("无图时 GraphJSONL 应 false")
	}
}

// TestGraphCorruptStatus：损坏的图 → corrupt（不伪装成 absent）。
func TestGraphCorruptStatus(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	id := st.Save(&engine.Result{URL: "http://t/", Graph: sampleGraph()}, nil)
	// 破坏图文件。
	if err := os.WriteFile(filepath.Join(dir, "graph", itoa(id), "graph.jsonl"),
		[]byte("{not json}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, status := st.GraphWithStatus(id)
	if status != "corrupt" {
		t.Errorf("应 corrupt，实得 %q", status)
	}
}

// TestDeleteRemovesGraph：删除记录同步删除图目录（不留孤儿）。
func TestDeleteRemovesGraph(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	id := st.Save(&engine.Result{URL: "http://t/", Graph: sampleGraph()}, nil)
	if !st.HasGraph(id) {
		t.Fatal("前置：应有图")
	}
	if !st.Delete(id) {
		t.Fatal("删除应成功")
	}
	if st.HasGraph(id) {
		t.Error("删除记录后图目录应一并删除")
	}
}

// TestClearAllRemovesGraphs：清空历史同样清空图。
func TestClearAllRemovesGraphs(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	id1 := st.Save(&engine.Result{URL: "http://a/", Graph: sampleGraph()}, nil)
	id2 := st.Save(&engine.Result{URL: "http://b/", Graph: sampleGraph()}, nil)
	if n := st.ClearAll(); n != 2 {
		t.Errorf("ClearAll = %d，期望 2", n)
	}
	if st.HasGraph(id1) || st.HasGraph(id2) {
		t.Error("清空后不应残留图")
	}
	if ids := st.GraphIDs(); len(ids) != 0 {
		t.Errorf("GraphIDs 应为空，实得 %v", ids)
	}
}

// TestHistoryShapeUnchanged：无图记录的 history.json 形态与 3.0 一致（无 graph 键）。
func TestHistoryShapeUnchanged(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	st.Save(&engine.Result{URL: "http://t/", ScannedAt: "x"}, map[string]any{"deep": true})
	raw, _ := os.ReadFile(filepath.Join(dir, "history.json"))
	if containsKey(raw, "graph") {
		t.Error("无图记录的 history.json 不应出现 graph 键（3.0 形态）")
	}
}

// ---- 测试辅助 ----

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// containsKey 判断字节里是否含指定键（JSONL 整体非合法 JSON，
// 故只看首行——header 是首行）。
func containsKey(raw []byte, key string) bool {
	first := raw
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			first = raw[:i]
			break
		}
	}
	return jsonContains(first, `"`+key+`"`)
}

func jsonContains(raw []byte, sub string) bool {
	for i := 0; i+len(sub) <= len(raw); i++ {
		if string(raw[i:i+len(sub)]) == sub {
			return true
		}
	}
	return false
}

// TestSaveGraphStampsScanID：落盘时回填 scan_id，使导出 JSONL 的 header 自带它
// （5.0 读端据此关联来源扫描）。
func TestSaveGraphStampsScanID(t *testing.T) {
	dir := t.TempDir()
	st, _ := New(dir, 10)
	g := sampleGraph() // 初始 ScanID 为空（模拟扫描流程产出）
	id := st.Save(&engine.Result{URL: "http://t/", Graph: g}, nil)

	if g.ScanID == "" {
		t.Error("Save 应在图未填 ScanID 时回填 scan_id")
	}
	if g.ScanID != itoa(id) {
		t.Errorf("回填的 ScanID = %q，期望 %q", g.ScanID, itoa(id))
	}
	// 读回时 header 应携带 scan_id。
	got, ok := st.Graph(id)
	if !ok || got.ScanID != itoa(id) {
		t.Errorf("读回的图 ScanID = %q，期望 %q", got.ScanID, itoa(id))
	}
	// JSONL header 里也应体现。
	data, _ := st.GraphJSONL(id)
	if !containsKey(data, "scan_id") {
		t.Error("导出 JSONL 应含 scan_id")
	}
}
