package correlate

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

// fixture 构造一张含黑盒发现与白盒事实的图（两端证据齐备）。
func fixture() (*model.ScanGraph, string, string) {
	g := model.NewGraph("scan-x")

	// 黑盒：SQLi 命中，参数 id，URL 含 /user.php。
	bEv := model.NewEvidence("response", model.OriginBlackbox, "dast", "scan-x",
		"http://t/user.php?id=1", "", 0, "sql syntax error")
	g.Add(bEv)
	bb := model.NewVulnNode(model.OriginBlackbox, "sqli-error", "",
		"http://t/user.php?id=1", "id", "", 0, model.ObsPositive, "proven",
		model.ConfConfirmed, []string{bEv.ID})
	g.Add(bb)

	// 白盒：user.php 内 id 参数经变量流入 SQL sink。
	wSrc := model.NewEvidence("source", model.OriginWhitebox, "audit", "",
		"", "src/user.php", 3, "$id = $_GET['id']")
	wSink := model.NewEvidence("sink", model.OriginWhitebox, "audit", "",
		"", "src/user.php", 5, "mysql_query($sql)")
	g.Add(wSrc)
	g.Add(wSink)
	df := model.NewDataflow("php", "src/user.php", "getUser", "id", 5,
		&model.FlowNode{Kind: "source", File: "src/user.php", Func: "getUser", Line: 3},
		&model.FlowNode{Kind: "sink", File: "src/user.php", Func: "getUser", Line: 5},
		nil, model.ConfConfirmed, []string{wSrc.ID, wSink.ID})
	g.Add(df)

	// 不相关的白盒事实（不同文件、不同参数）——不应被关联。
	uSrc := model.NewEvidence("sink", model.OriginWhitebox, "audit", "",
		"", "src/other.py", 9, "os.system(x)")
	g.Add(uSrc)
	df2 := model.NewDataflow("python", "src/other.py", "run", "cmd", 9,
		&model.FlowNode{Kind: "source", File: "src/other.py", Func: "run", Line: 7},
		&model.FlowNode{Kind: "sink", File: "src/other.py", Func: "run", Line: 9},
		nil, model.ConfProbable, []string{uSrc.ID})
	g.Add(df2)
	return g, bb.ID, df.ID
}

// TestCorrelateByParam：参数名一致 → basis=param，link 两端正确。
func TestCorrelateByParam(t *testing.T) {
	g, bbID, dfID := fixture()
	res := Run(g, Options{})
	if len(res.Links) == 0 {
		t.Fatal("应产出至少一条关联")
	}
	var byParam *model.EvidenceLink
	for i := range res.Links {
		if res.Links[i].Basis == "param" {
			byParam = &res.Links[i]
		}
	}
	if byParam == nil {
		t.Fatal("应按 param 依据关联")
	}
	if byParam.BlackboxVulnID != bbID || byParam.WhiteboxDataflowID != dfID {
		t.Errorf("关联两端不符：%s / %s", byParam.BlackboxVulnID, byParam.WhiteboxDataflowID)
	}
	if len(byParam.EvidenceIDs) == 0 {
		t.Error("关联边必须带证据（需求：无证据不成边）")
	}
	if byParam.Confidence == model.ConfConfirmed {
		t.Error("自动关联不得给 confirmed（应由人确认）")
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("关联后图应通过校验：%v", err)
	}
}

// TestCorrelateIdempotent：重复 Run 不产生重复边。
func TestCorrelateIdempotent(t *testing.T) {
	g, _, _ := fixture()
	first := len(Run(g, Options{}).Links)
	second := len(Run(g, Options{}).Links)
	if second != 0 {
		t.Errorf("二次关联应零新增，实得 %d", second)
	}
	if first == 0 {
		t.Fatal("首次应有新增")
	}
}

// TestCorrelateSkipsUnrelated：无共享参数的无关白盒事实不应被关联。
func TestCorrelateSkipsUnrelated(t *testing.T) {
	g, _, dfID := fixture()
	Run(g, Options{})
	for _, l := range g.EvidenceLinks {
		if l.WhiteboxDataflowID == dfID {
			continue // 期望关联的那条
		}
		// 其它边若指向 other.py 则说明误报。
		for i := range g.Dataflows {
			if g.Dataflows[i].ID == l.WhiteboxDataflowID && g.Dataflows[i].File == "src/other.py" {
				t.Errorf("无关事实被误关联：%+v", l)
			}
		}
	}
}

// TestCorrelateURLBasis：无参数重合但文件路径重合时走 basis=url。
func TestCorrelateURLBasis(t *testing.T) {
	g := model.NewGraph("s")
	bEv := model.NewEvidence("response", model.OriginBlackbox, "check", "s",
		"http://t/admin.php", "", 0, "admin exposed")
	g.Add(bEv)
	bb := model.NewVulnNode(model.OriginBlackbox, "admin-path", "",
		"http://t/admin.php", "", "", 0, model.ObsPositive, "detected",
		model.ConfProbable, []string{bEv.ID})
	g.Add(bb)
	wEv := model.NewEvidence("snippet", model.OriginWhitebox, "audit", "",
		"", "app/admin.php", 1, "<?php")
	g.Add(wEv)
	vn := model.NewVulnNode(model.OriginWhitebox, "", "PHP-CMD", "", "", "app/admin.php", 1,
		model.ObsPositive, "detected", model.ConfProbable, []string{wEv.ID})
	g.Add(vn)

	res := Run(g, Options{})
	found := false
	for _, l := range res.Links {
		if l.Basis == "url" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应按 url 依据关联（文件名 admin.php 重合）；links=%+v", res.Links)
	}
}

// TestCorrelateTechOptIn：tech 弱关联默认关，开启后生效。
func TestCorrelateTechOptIn(t *testing.T) {
	g := model.NewGraph("s")
	bEv := model.NewEvidence("response", model.OriginBlackbox, "js", "s", "http://t/a", "", 0, "x")
	g.Add(bEv)
	// checkID 用语言名以触发 tech 依据。
	bb := model.NewVulnNode(model.OriginBlackbox, "javascript", "", "http://t/a", "", "", 0,
		model.ObsPositive, "detected", model.ConfProbable, []string{bEv.ID})
	g.Add(bb)
	wEv := model.NewEvidence("sink", model.OriginWhitebox, "audit", "", "", "z.mjs", 1, "eval(x)")
	g.Add(wEv)
	df := model.NewDataflow("javascript", "z.mjs", "f", "p", 1,
		&model.FlowNode{Kind: "source", Line: 1}, &model.FlowNode{Kind: "sink", Line: 2},
		nil, model.ConfProbable, []string{wEv.ID})
	g.Add(df)

	if got := len(Run(g, Options{}).Links); got != 0 {
		t.Errorf("tech 依据默认关，不应关联，实得 %d", got)
	}
	// 同一张图再跑（注意：默认关那次未建边，图仍干净）。
	if got := len(Run(g, Options{IncludeTech: true}).Links); got == 0 {
		t.Error("开启 IncludeTech 后应产生 tech 关联")
	}
}

// TestCorrelateEmptyGraph：空图/单侧为空时不 panic、不产边。
func TestCorrelateEmptyGraph(t *testing.T) {
	if r := Run(nil, Options{}); len(r.Links) != 0 {
		t.Error("nil 图应返回空结果")
	}
	g := model.NewGraph("s")
	if r := Run(g, Options{}); len(r.Links) != 0 {
		t.Error("空图应返回空结果")
	}
}

// TestJudgePrecedence：param 优先于 url。
func TestJudgePrecedence(t *testing.T) {
	b := blackboxNode{Vuln: model.VulnNode{ID: "vn_b"}, Params: map[string]bool{"id": true},
		Paths: map[string]bool{"user.php": true}, Techs: map[string]bool{}}
	w := whiteboxFact{df: &model.Dataflow{ID: "df_w"}, Params: map[string]bool{"id": true},
		FileBase: "user.php", PathParts: map[string]bool{"user.php": true}}
	basis, score := judge(b, w, Options{})
	if basis != "param" || score != 100 {
		t.Errorf("param 应优先，实得 (%s,%d)", basis, score)
	}
}
