package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

// writeIntelDump 写一份最小 intel_dump.json.gz（一张 vuln_kb 表）。
func writeIntelDump(t *testing.T, products []string) string {
	t.Helper()
	rows := []map[string]any{}
	for i, prod := range products {
		rows = append(rows, map[string]any{
			"id": i + 1, "product": prod, "cve": "CVE-2021-100" + string(rune('0'+i)),
			"name": prod + " 漏洞", "severity": "high",
		})
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(map[string]any{
		"tables": map[string]any{"vuln_kb": rows},
	}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "intel_dump.json.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// affectedCVEs 把指纹技术名映射到受影响 CVE（intel 关联产出）。
func TestAffectedCVEsFromTech(t *testing.T) {
	dump := writeIntelDump(t, []string{"Apache Tomcat"})
	kb, err := intel.Load(dump, "")
	if err != nil {
		t.Fatalf("intel.Load: %v", err)
	}
	e := &Engine{}
	e.SetKB(kb)
	got := e.affectedCVEs([]Tech{{Name: "Apache Tomcat", Version: "9.0.0"}})
	if len(got) != 1 || !got["CVE-2021-1000"] {
		t.Fatalf("应从指纹得到受影响 CVE，实得 %v", got)
	}
}

// KB 未挂载 / 技术为空 → 空集（调度退回纯 tag+LRU，零回归）。
func TestAffectedCVEsNoKB(t *testing.T) {
	e := &Engine{}
	if got := e.affectedCVEs([]Tech{{Name: "Apache Tomcat"}}); got != nil {
		t.Fatalf("KB 未挂载应返回 nil，实得 %v", got)
	}
	dump := writeIntelDump(t, []string{"Apache Tomcat"})
	kb, err := intel.Load(dump, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetKB(kb)
	if got := e.affectedCVEs(nil); got != nil {
		t.Fatalf("无技术应返回 nil，实得 %v", got)
	}
}

// CVE 数封顶：指纹繁多的目标不得让 CVE 通道反查集无界膨胀。
func TestAffectedCVEsCapped(t *testing.T) {
	prods := []string{}
	for i := 0; i < 200; i++ {
		prods = append(prods, "Product"+string(rune('A'+i%26))+string(rune('a'+i/26)))
	}
	dump := writeIntelDump(t, prods)
	kb, err := intel.Load(dump, "")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	e.SetKB(kb)
	techs := []Tech{}
	for _, p := range prods {
		techs = append(techs, Tech{Name: p})
	}
	got := e.affectedCVEs(techs)
	if len(got) > maxAffectedCVEs {
		t.Fatalf("CVE 集应封顶 %d，实得 %d", maxAffectedCVEs, len(got))
	}
}

// 端到端：CVE 通道把「目标指纹受影响的 CVE」对应的模板提进本次预算，
// 即使该模板不带任何与指纹匹配的 tag（此前只能等 LRU 轮转碰到）。
func TestNucleiSubsetCVEChannel(t *testing.T) {
	dump := writeIntelDump(t, []string{"Apache Tomcat"})
	kb, err := intel.Load(dump, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// 模板 A：声明 CVE-2021-1000（目标受影响），但不带 tomcat tag
	tplA := `id: CVE-2021-1000
info:
  name: Tomcat CVE probe
  severity: high
  tags: cve,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "probe-ok"
`
	// 模板 B：无关模板（无 CVE、无匹配 tag）
	tplB := `id: unrelated-check
info:
  name: Unrelated
  severity: info
  tags: misc
http:
  - method: GET
    path:
      - "{{BaseURL}}/other"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "other-ok"
`
	// 诱饵：路径字典序更前（纯 LRU/相关度下会抢走唯一名额）
	decoy := `id: decoy-tagmatch
info:
  name: Decoy tag match
  severity: high
  tags: tomcat
http:
  - method: GET
    path:
      - "{{BaseURL}}/decoy"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "decoy-ok"
`
	if err := os.WriteFile(filepath.Join(dir, "0-decoy.yaml"), []byte(decoy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(tplA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(tplB), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Checks.NucleiDir = dir
	cfg.Checks.NucleiCap = 1
	cfg.Store.DataDir = t.TempDir()
	e := testEngine(cfg)
	e.SetKB(kb)
	e.nucleiLRU = map[string]int64{}

	// cap=1：CVE 通道若不生效，预算会被 LRU/相关度给到别的模板；
	// 生效则唯一名额给声明受影响 CVE 的模板 A。
	sel, stat := e.nucleiSubset([]Tech{{Name: "Apache Tomcat", Version: "9.0.0"}}, "", 1)
	if stat == nil {
		t.Fatal("stat 不应为空")
	}
	if stat["cve_total"].(int) != 1 {
		t.Fatalf("cve_total 应为 1，实得 %v", stat["cve_total"])
	}
	if stat["cve_hits"].(int) != 1 {
		t.Fatalf("cve_hits 应为 1，实得 %v", stat["cve_hits"])
	}
	if len(sel) == 0 {
		t.Fatal("应选出一条模板")
	}
	found := false
	for _, c := range sel {
		if strings.Contains(c.ID, "CVE-2021-1000") {
			found = true
		}
	}
	if !found {
		t.Fatalf("CVE 通道未把受影响 CVE 的模板提进预算，实得 %+v", sel)
	}
}
