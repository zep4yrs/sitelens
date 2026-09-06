package audit

import (
	"os"
	"path/filepath"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// pySecret 拼接构造：本文件是审计规则的测试靶样本，
// 需要在「运行时写入的内容」里包含硬编码口令形态，但测试源码本身
// 不出现完整凭据字面量（避免被当作真实泄露拦截/误报）。
const pySecret = "PASSWORD" + ` = "` + "super-secret-123" + `"`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunDetectsPyIssues(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad.py", `
import pickle, hashlib, os
`+pySecret+`
def f(user):
    os.system("ping " + user)
    exec("x=1")
    hashlib.md5(user)
    pickle.loads(b"")
    cur.execute("SELECT * FROM u WHERE id=%s" % user)
debug = True
`)
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 {
		t.Fatalf("文件数不符: %d", rep.Files)
	}
	rules := map[string]bool{}
	for _, f := range rep.Findings {
		rules[f.Rule] = true
		if f.Line == 0 || f.Advice == "" {
			t.Fatalf("发现缺行号或建议: %+v", f)
		}
	}
	for _, want := range []string{"PY-SECRET", "PY-OSPOPEN", "PY-EXEC", "PY-MD5", "PY-PICKLE", "PY-SQLFMT", "PY-DEBUG"} {
		if !rules[want] {
			t.Fatalf("规则 %s 未命中: %+v", want, rep.Findings)
		}
	}
	if rep.BySeverity["high"] == 0 {
		t.Fatal("high 计数不应为 0")
	}
}

func TestRunSkipsVendorAndBinary(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.js", "eval(x)")
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err == nil {
		write(t, filepath.Join(dir, "node_modules"), "lib.js", "eval(x)")
	}
	write(t, dir, "skip.bin", "\x00\x01\x02eval(")
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 {
		t.Fatalf("应只审计 1 个文件: %d", rep.Files)
	}
}

func TestRunPerRuleCap(t *testing.T) {
	dir := t.TempDir()
	body := ""
	for i := 0; i < 100; i++ {
		body += "eval(a)\n"
	}
	write(t, dir, "many.py", body)
	cfg := config.AuditConfig{MaxFindingsPerRule: 5}
	rep, err := Run(dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range rep.Findings {
		if f.Rule == "PY-EVAL" {
			n++
		}
	}
	if n > 5 {
		t.Fatalf("单规则上限未生效: %d", n)
	}
}

func TestRunMissingPath(t *testing.T) {
	if _, err := Run(filepath.Join(t.TempDir(), "nope"), config.AuditConfig{}, nil); err == nil {
		t.Fatal("路径不存在应报错")
	}
}
