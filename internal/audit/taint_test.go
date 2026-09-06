package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

func TestTaintFileTracesFlow(t *testing.T) {
	src := `import os
name = request.args.get("name")
safe = "constant"
os.system("ping " + name)
os.system("ping " + safe)
subprocess.run(name, shell=True)
`
	lines := strings.Split(src, "\n")
	findings := taintFile("f.py", lines)
	if len(findings) < 2 {
		t.Fatalf("应至少命中 2 处（os.system + subprocess.run）: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule != "TAINT-os.system" && f.Rule != "TAINT-subprocess.run" {
			t.Fatalf("规则名异常: %s", f.Rule)
		}
		if !strings.Contains(f.Advice, "name") {
			t.Fatalf("建议应提及污点变量: %+v", f)
		}
	}
	// safe 常量不应报
	for _, f := range findings {
		if strings.Contains(f.Match, "safe") {
			t.Fatalf("常量不应被污点追踪: %+v", f)
		}
	}
}

func TestTaintNoSourceNoFinding(t *testing.T) {
	src := `import os
user = "admin"
os.system("ping " + user)
`
	findings := taintFile("f.py", strings.Split(src, "\n"))
	if len(findings) != 0 {
		t.Fatalf("无污点源不应命中: %+v", findings)
	}
}

func TestTaintIntegratedInRun(t *testing.T) {
	dir := t.TempDir()
	src := `import os
q = input("name: ")
os.system("echo " + q)
`
	if err := os.WriteFile(filepath.Join(dir, "flow.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(dir, config.AuditConfig{MaxFindingsPerRule: 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Rule, "TAINT-") {
			found = true
			if f.File == "" {
				t.Fatal("TAINT 发现应带文件路径")
			}
		}
	}
	if !found {
		t.Fatalf("Run 应包含 TAINT 发现: %+v", rep.Findings)
	}
}
