package nuclei

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- B2-06 协议模板 dsl 环境：未知变量不得伪造取值 ----

// TestNetEnvUnavailable B2-06 回归：协议模板没有 HTTP 状态码/响应头/Host 语义，
// 这些变量必须报"不可用"→ 不命中；此前伪造 0/空串会让含 `!=`/取反的表达式恒真。
func TestNetEnvUnavailable(t *testing.T) {
	// 1) `status_code != 200` 在协议模板里必须不可判定（此前 0 != 200 恒真）
	p, err := compileNetDSL("status_code != 200")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, err := p.Eval(netEnv{response: "anything"}); ok || err == nil {
		t.Fatalf("status_code 不可用时应报错且不命中，got ok=%v err=%v", ok, err)
	}

	// 2) `!contains(header['X'],'y')` 同理（此前 header 为空串 → 取反恒真）
	p2, err := compileNetDSL(`!contains(header['X'],'y')`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, err := p2.Eval(netEnv{response: "anything"}); ok || err == nil {
		t.Fatalf("header 不可用时应报错且不命中，got ok=%v err=%v", ok, err)
	}

	// 3) `host != 'x'` 同理
	p3, err := compileNetDSL("host != 'x'")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if ok, err := p3.Eval(netEnv{response: "anything"}); ok || err == nil {
		t.Fatalf("host 不可用时应报错且不命中，got ok=%v err=%v", ok, err)
	}

	// 4) 协议模板真正的判定面（response 变量）必须照常工作
	p4, err := compileNetDSL(`contains(response, 'SSH-2.0')`)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	ok4, err4 := p4.Eval(netEnv{response: "SSH-2.0-OpenSSH_8.9"})
	if err4 != nil || !ok4 {
		t.Fatalf("response 变量应可用，got ok=%v err=%v", ok4, err4)
	}
	if ok5, _ := p4.Eval(netEnv{response: "HTTP/1.1 200 OK"}); ok5 {
		t.Fatal("不含 SSH-2.0 的响应不应命中")
	}
}

// TestNetDSLPositiveGroundGate B2-06：协议模板 dsl 也要求"正向内容判定"，
// 纯排除式/恒真表达式不得转换成 check（与 buildChecks 同口径）。
func TestNetDSLPositiveGroundGate(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{`contains(response, 'x')`, true},
		{`!contains(response, 'x')`, false}, // 纯排除式：对任意响应可能恒真
		{`true`, false},                     // 恒真
		{`contains(response, 'a') && !contains(response, 'b')`, true},
	}
	for _, c := range cases {
		p, err := compileNetDSL(c.expr)
		if err != nil {
			t.Fatalf("%s 编译失败: %v", c.expr, err)
		}
		if got := p.PositiveGround(); got != c.want {
			t.Errorf("%s PositiveGround=%v, want %v", c.expr, got, c.want)
		}
	}
}

// ---- B2-11 索引 walk 错误传播 ----

// TestWalkTemplateFilesReportsError B2-11 回归：walk 期错误必须上抛，
// 不得静默返回残缺文件集合。
func TestWalkTemplateFilesReportsError(t *testing.T) {
	dir := t.TempDir()
	tpl := "id: a\ninfo:\n  name: A\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	// 正常目录：无错误
	if _, _, err := walkTemplateFiles(dir); err != nil {
		t.Fatalf("正常目录不应报错: %v", err)
	}
	// 不存在的根目录：必须报错（旧实现 WalkDir 的 err 会经 return err 传回，
	// 但 per-entry 错误被吞；这里用不存在路径覆盖"根不可读"路径）
	if _, _, err := walkTemplateFiles(dir + "/does-not-exist"); err == nil {
		t.Fatal("不存在的模板根目录应返回错误（旧实现静默返回空集合）")
	}
}

// TestCachedIndexFresh B2-11：缓存目录戳校验入口的边界语义。
func TestCachedIndexFresh(t *testing.T) {
	// root 为空（旧缓存/手工构造）→ 无法校验，保持旧行为（视为新鲜）
	if !cachedIndexFresh("", nil) {
		t.Fatal("无 root 的缓存应保持旧行为（视为新鲜）")
	}
	// root 有值但戳为空 → 同样无法校验
	if !cachedIndexFresh("/tmp/x", nil) {
		t.Fatal("无目录戳时应保持旧行为")
	}
	// root 有值 + 戳指向不存在的目录 → 判定失效
	stamps := []dirStamp{{Path: ".", MTime: 12345}}
	if cachedIndexFresh("/definitely/not/exist/sitelens", stamps) {
		t.Fatal("目录不存在时缓存应判定失效")
	}
}
