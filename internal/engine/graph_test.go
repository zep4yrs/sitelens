package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// graphSite 一个可触发多源发现的靶站：敏感文件泄露（check）、
// 反射 XSS（dast）、缺 HttpOnly 的 Cookie（passive）、带参链接。
func graphSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 反射 XSS：原样回显 q 参数 + Set-Cookie 缺 HttpOnly（passive 命中）
		w.Header().Add("Set-Cookie", "sid=1; Path=/")
		if q := r.URL.Query().Get("q"); q != "" {
			_, _ = w.Write([]byte("<html><body>hello " + q + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte(`<html><body><a href="/?q=1">p</a></body></html>`))
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ref: refs/heads/main\n")) // check git-leak 命中
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// scanWithGraph 以 graph 开关扫描靶站，返回结果。
func scanWithGraph(t *testing.T, opts Options) *Result {
	t.Helper()
	srv := graphSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.DAST.MaxParams = 4
	cfg.DAST.TimeBlind = false
	cfg.DAST.BoolBlind = false
	e := New(cfg, nil, nil)
	opts.Graph = true
	return e.Scan(srv.URL, opts, nil, nil)
}

// TestGraphDisabledByDefault：不开 Graph 时 Result.Graph 为 nil，
// 且 JSON 不出现 graph 键——3.0 输出形态不变。
func TestGraphDisabledByDefault(t *testing.T) {
	srv := graphSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	e := New(cfg, nil, nil)
	res := e.Scan(srv.URL, Options{Deep: true, Passive: true, Checks: "none"}, nil, nil)
	if res.Graph != nil {
		t.Fatal("默认应不收集图")
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"graph"`) {
		t.Fatal("JSON 不应出现 graph 键（omitempty 失效）")
	}
}

// TestGraphOptInPopulates：开启 Graph 后图被填充并通过自校验。
func TestGraphOptInPopulates(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true, DAST: true, Checks: "core"})
	if res.Error != "" {
		t.Fatalf("扫描不应报错：%s", res.Error)
	}
	if res.Graph == nil {
		t.Fatal("开启 Graph 应产出图")
	}
	if res.Graph.Schema != model.SchemaVersion {
		t.Errorf("schema = %q，期望 %q", res.Graph.Schema, model.SchemaVersion)
	}
	if err := res.Graph.Validate(); err != nil {
		t.Fatalf("产出的图应通过校验：%v", err)
	}
	c := res.Graph.Counts()
	t.Logf("graph counts: %v (verified=%d)", c, len(res.Verified))
	if c[model.KindVulnNode] == 0 {
		t.Error("图应含 vuln_node")
	}
	if c[model.KindEvidence] == 0 {
		t.Error("图应含 evidence")
	}
}

// TestGraphVerifiedParity：graph 开关不改变 verified 条目数（适配器不丢发现）。
func TestGraphVerifiedParity(t *testing.T) {
	srv := graphSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.DAST.MaxParams = 4
	cfg.DAST.TimeBlind = false
	cfg.DAST.BoolBlind = false
	e := New(cfg, nil, nil)
	opts := Options{Deep: true, Passive: true, DAST: true, Checks: "core"}
	off := e.Scan(srv.URL, opts, nil, nil)

	opts.Graph = true
	on := e.Scan(srv.URL, opts, nil, nil)

	if len(on.Verified) != len(off.Verified) {
		t.Fatalf("verified 数不一致：关=%d 开=%d", len(off.Verified), len(on.Verified))
	}
	// 键位集合一致（map 形态未被改动）。
	if off.Verified != nil && len(off.Verified) == len(on.Verified) {
		for i := range off.Verified {
			if len(off.Verified[i]) != len(on.Verified[i]) {
				t.Errorf("第 %d 条 verified 键数不一致", i)
			}
		}
	}
}

// TestGraphJSONCompatVerifiedKeys：开图后 JSON 里 verified 的键位仍是 3.0 形态。
func TestGraphJSONCompatVerifiedKeys(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true})
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Verified []map[string]any `json:"verified"`
		Graph    *model.ScanGraph `json:"graph"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("结果 JSON 应可解析：%v", err)
	}
	if decoded.Graph == nil {
		t.Fatal("graph 应出现在 JSON 中")
	}
	for _, v := range decoded.Verified {
		if _, ok := v["check"]; !ok {
			t.Errorf("verified 条目缺 check 键：%v", v)
		}
	}
}

// TestGraphPositiveEvidence：所有 positive 的 vuln_node 都带真实证据（需求 9）。
func TestGraphPositiveEvidence(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true, DAST: true, Checks: "core"})
	if res.Graph == nil {
		t.Fatal("应有图")
	}
	for _, v := range res.Graph.VulnNodes {
		if v.Observation == model.ObsPositive && len(v.EvidenceIDs) == 0 {
			t.Errorf("positive 节点 %s（%s）无证据", v.ID, v.CheckID)
		}
	}
}

// TestGraphEntNoConfirmedWithoutEvidence：无证据的 confirmed 不存在（需求 9）。
func TestGraphNoConfirmedWithoutEvidence(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true, DAST: true, Checks: "core"})
	for _, v := range res.Graph.VulnNodes {
		if v.Confidence == model.ConfConfirmed && len(v.EvidenceIDs) == 0 {
			t.Errorf("confirmed 节点 %s 无证据", v.ID)
		}
	}
	for _, l := range res.Graph.EvidenceLinks {
		if l.Confidence == model.ConfConfirmed && len(l.EvidenceIDs) == 0 {
			t.Errorf("confirmed 关联 %s 无证据", l.ID)
		}
	}
}

// TestGraphJSONLRoundTrip：引擎产出的图可写为 JSONL 并读回。
func TestGraphJSONLRoundTrip(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true, Checks: "core"})
	if res.Graph == nil {
		t.Fatal("应有图")
	}
	data, err := res.Graph.MarshalJSONL()
	if err != nil {
		t.Fatalf("序列化 JSONL：%v", err)
	}
	got, err := model.UnmarshalJSONL(data)
	if err != nil {
		t.Fatalf("读回 JSONL：%v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("读回的图应通过校验：%v", err)
	}
	a, b := res.Graph.Counts(), got.Counts()
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("%s 计数往返不一致：%d → %d", k, a[k], b[k])
		}
	}
}

// TestGraphEntryPointsCollected：带参链接与表单转为入口点实体。
func TestGraphEntryPointsCollected(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, Passive: true})
	if res.Graph == nil || len(res.Graph.EntryPoints) == 0 {
		t.Fatal("应收集到入口点")
	}
	foundParam := false
	for _, ep := range res.Graph.EntryPoints {
		if ep.Kind == "param" && ep.Param != "" {
			foundParam = true
		}
	}
	if !foundParam {
		t.Error("应至少有一个带参入口点")
	}
}

// TestGraphDASTImpact：DAST 命中进入图，且参数被记入节点（无 exploit 时无 impact）。
func TestGraphDASTFinding(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, DAST: true, Passive: true})
	if res.Graph == nil {
		t.Fatal("应有图")
	}
	found := false
	for _, v := range res.Graph.VulnNodes {
		if v.CheckID == "xss-reflect" {
			found = true
			if v.Param != "q" {
				t.Errorf("xss 节点参数 = %q，期望 q", v.Param)
			}
			if v.Observation != model.ObsPositive || len(v.EvidenceIDs) == 0 {
				t.Error("xss 命中应为 positive 且带证据")
			}
		}
	}
	if !found {
		t.Error("靶站反射 XSS 应产出 xss-reflect 节点")
	}
}

// TestGraphCWEAttachment：黑盒 check 命中挂 CWE 关联。
func TestGraphCWEAttachment(t *testing.T) {
	res := scanWithGraph(t, Options{Deep: true, DAST: true, Passive: true})
	if res.Graph == nil {
		t.Fatal("应有图")
	}
	if len(res.Graph.CWERels) == 0 {
		t.Fatal("应产出 CWE 关联")
	}
	has89or79 := false
	for _, r := range res.Graph.CWERels {
		if r.CWEID == "CWE-89" || r.CWEID == "CWE-79" {
			has89or79 = true
		}
		// 每条 CWE 关联的主体必须图内可解析。
		if r.SubjectKind != "cve" {
			found := false
			for _, v := range res.Graph.VulnNodes {
				if v.ID == r.SubjectID {
					found = true
				}
			}
			if !found {
				t.Errorf("CWE 关联 %s 主体 %s 不可解析", r.ID, r.SubjectID)
			}
		}
	}
	if !has89or79 {
		t.Error("应含 SQLi/XSS 的 CWE 关联")
	}
}

// TestGraphStableAcrossRescans：同靶站两次扫描的实体 ID 集合一致（稳定 ID 收益）。
func TestGraphStableAcrossRescans(t *testing.T) {
	srv := graphSite(t)
	cfg := config.Default()
	cfg.Scan.Resolve = false
	cfg.Scan.RateIntervalMS = 0
	cfg.DAST.MaxParams = 4
	cfg.DAST.TimeBlind = false
	cfg.DAST.BoolBlind = false
	e := New(cfg, nil, nil)
	opts := Options{Deep: true, Passive: true, DAST: true, Checks: "core", Graph: true}

	ids := func(res *Result) map[string]bool {
		m := map[string]bool{}
		for _, x := range res.Graph.SortedEntities() {
			// 排除指纹类情报证据（版本/顺序可能受外部数据影响）。
			m[x.EntityID()] = true
		}
		return m
	}
	first := ids(e.Scan(srv.URL, opts, nil, nil))
	second := ids(e.Scan(srv.URL, opts, nil, nil))
	for id := range first {
		if !second[id] {
			t.Errorf("重扫后实体 ID 丢失：%s", id)
		}
	}
}
