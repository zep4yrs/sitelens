package astx

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSupportedLangs：当前可 AST 解析的语言为 python/js/php/java/go。
// PHP 的 grammar 由本仓第一方自持（internal/astx/phpgram），见 astx.go 说明。
func TestSupportedLangs(t *testing.T) {
	got := Supported()
	if len(got) != 5 {
		t.Fatalf("AST 支持语言数 = %d，期望 5", len(got))
	}
	for _, l := range []Lang{LangPython, LangJS, LangPHP, LangJava, LangGo} {
		if !ASTSupported(l) {
			t.Errorf("应支持 %s", l)
		}
	}
}

// TestDetectLang：后缀 → 语言映射。PHP 返回不支持（audit 将回退行级正则）。
func TestDetectLang(t *testing.T) {
	cases := map[string]Lang{
		"a.py": LangPython, "a.PY": LangPython, "b.js": LangJS, "b.mjs": LangJS,
		"c.php": LangPHP, "d.java": LangJava, "e.go": LangGo,
		"/x/y/z.py": LangPython,
	}
	for path, want := range cases {
		if l, ok := DetectLang(path); !ok || l != want {
			t.Errorf("DetectLang(%q) = (%v,%v)，期望 %v", path, l, ok, want)
		}
	}
	// 其它不在 AST 范围 → 不支持（调用方回退行级）。
	for _, bad := range []string{"a.txt", "a", "a.rb", "a.html"} {
		if _, ok := DetectLang(bad); ok {
			t.Errorf("DetectLang(%q) 应不支持 AST", bad)
		}
	}
}

// TestCWEForSink：sink 分类 → CWE 映射。
func TestCWEForSink(t *testing.T) {
	want := map[string]string{
		SinkExecCmd: "CWE-78", SinkCodeExec: "CWE-95", SinkSQL: "CWE-89",
		SinkDeser: "CWE-502", SinkPath: "CWE-22", SinkWeakHash: "CWE-916",
		SinkTemplate: "CWE-1336",
	}
	for k, v := range want {
		if got := CWEForSink(k); got != v {
			t.Errorf("CWEForSink(%q) = %q，期望 %q", k, got, v)
		}
	}
	if CWEForSink("nope") != "" {
		t.Error("未收录 sink 应返回空串")
	}
}

// TestWordIn：标识符边界匹配（递归取证函数核心正确性）。
func TestWordIn(t *testing.T) {
	cases := []struct {
		text, v string
		want    bool
	}{
		{"os.system(cmd)", "cmd", true},
		{"os.system(cmdline)", "cmd", false}, // 不误配前缀
		{"f(x, y)", "x", true},
		{"f(xx, y)", "x", false},
		{"$id . $suffix", "$id", true},
		{"a.b.c", "b", true},
		{"", "x", false},
		{"x", "", false},
	}
	for _, c := range cases {
		if got := wordIn(c.text, c.v); got != c.want {
			t.Errorf("wordIn(%q,%q) = %v，期望 %v", c.text, c.v, got, c.want)
		}
	}
}

// TestNoCGOStubBehavior：非 CGO 构建下，Available=false 且 API 返回 ErrUnavailable。
// 该测试在 Windows（桩）与 WSL（CGO）下断言相反分支——用 Available() 分流。
func TestStubOrCGO(t *testing.T) {
	if Available() {
		// CGO 构建：解析能力应可用（由 testdata 用例覆盖）。
		if _, err := AnalyzeSource("x.py", []byte("x=1\n")); err != nil {
			t.Fatalf("CGO 构建应可解析：%v", err)
		}
		return
	}
	// 桩构建：一律 ErrUnavailable，且不得假装成功。
	if _, err := AnalyzeSource("x.py", []byte("x=1\n")); err != ErrUnavailable {
		t.Errorf("桩构建应返回 ErrUnavailable，实得 %v", err)
	}
	if _, err := AnalyzeFile("x.py"); err != ErrUnavailable {
		t.Errorf("AnalyzeFile 桩应返回 ErrUnavailable，实得 %v", err)
	}
}

// TestUnsupportedLangAlwaysErrors：不支持语言在两种构建下都报错。
func TestUnsupportedLangAlwaysErrors(t *testing.T) {
	if _, err := AnalyzeSource("x.rb", []byte("puts 1\n")); err != ErrUnsupportedLang {
		t.Errorf("不支持语言应 ErrUnsupportedLang，实得 %v", err)
	}
}

// ---- 以下用例只在 CGO 构建（WSL/CI）下运行真实 AST 解析 ----

// TestAnalyzePythonFlow：Python 污点链 source→sink 应被识别。
func TestAnalyzePythonFlow(t *testing.T) {
	if !Available() {
		t.Skip("需 CGO 构建")
	}
	src, err := os.ReadFile(filepath.Join("testdata", "vuln.py"))
	if err != nil {
		t.Fatal(err)
	}
	an, err := AnalyzeSource("vuln.py", src)
	if err != nil {
		t.Fatal(err)
	}
	// 函数清单应含 handler / safe_handler / direct_sink。
	names := map[string]bool{}
	for _, f := range an.Functions {
		names[f.Name] = true
	}
	for _, want := range []string{"handler", "safe_handler", "direct_sink"} {
		if !names[want] {
			t.Errorf("函数清单缺少 %s（实得 %v）", want, names)
		}
	}
	// handler 内：request.args（source）经变量 cmd 流入 os.system（exec_cmd sink）。
	var found bool
	for _, fl := range an.Flows {
		if fl.Func == "handler" && fl.Sink.Sink == SinkExecCmd && fl.Sink.CWE == "CWE-78" {
			found = true
			if fl.Var != "cmd" {
				t.Errorf("期望污点变量 cmd，实得 %q", fl.Var)
			}
			if fl.Source.Line == 0 || fl.Sink.Line == 0 {
				t.Error("source/sink 应带行号")
			}
			if len(fl.Steps) == 0 {
				t.Error("应记录污点传播步骤")
			}
		}
	}
	if !found {
		t.Errorf("未识别 handler 的 source→sink 流；flows=%+v", an.Flows)
	}
	// direct_sink 内：input() 直接进 os.system（情形 b）。
	var direct bool
	for _, fl := range an.Flows {
		if fl.Func == "direct_sink" && fl.Var == "<direct>" {
			direct = true
		}
	}
	if !direct {
		t.Error("未识别 source 直接进 sink 的情形")
	}
	// safe_handler 不含 sink。
	for _, fl := range an.Flows {
		if fl.Func == "safe_handler" {
			t.Errorf("safe_handler 不应有数据流：%+v", fl)
		}
	}
}

// TestAnalyzeJavaSQLFlow：Java 污点链 + sink 分类（SQL），覆盖第二种语言。
func TestAnalyzeJavaSQLFlow(t *testing.T) {
	if !Available() {
		t.Skip("需 CGO 构建")
	}
	src := []byte(`class Handler {
  void handle(HttpServletRequest request) {
    String id = request.getParameter("id");
    String sql = "SELECT * FROM users WHERE id=" + id;
    stmt.executeQuery(sql);
  }
  void safe(HttpServletRequest request) {
    String name = request.getParameter("name");
    System.out.println(name);
  }
}
`)
	an, err := AnalyzeSource("Handler.java", src)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, fl := range an.Flows {
		if fl.Func == "handle" && fl.Sink.Sink == SinkSQL && fl.Sink.CWE == "CWE-89" {
			found = true
		}
	}
	if !found {
		t.Errorf("未识别 Java SQL 注入流；flows=%+v", an.Flows)
	}
	for _, fl := range an.Flows {
		if fl.Func == "safe" {
			t.Errorf("safe 不应有数据流：%+v", fl)
		}
	}
}

// TestAnalyzeCallsAndFunctions：函数/调用关系抽取。
func TestAnalyzeCallsAndFunctions(t *testing.T) {
	if !Available() {
		t.Skip("需 CGO 构建")
	}
	src := []byte("import os\n\ndef a():\n    b()\n\ndef b():\n    os.system('ls')\n")
	an, err := AnalyzeSource("t.py", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(an.Functions) != 2 {
		t.Errorf("函数数 = %d，期望 2", len(an.Functions))
	}
	var callFound bool
	for _, c := range an.Calls {
		if c.Callee == "b" && c.Func == "a" {
			callFound = true
		}
	}
	if !callFound {
		t.Errorf("未抽取 a→b 调用关系；calls=%+v", an.Calls)
	}
}

// TestAnalyzeJSPathFlow：JS 语言可用性冒烟（source→sink）。
func TestAnalyzeJSPathFlow(t *testing.T) {
	if !Available() {
		t.Skip("需 CGO 构建")
	}
	src := []byte(`const fs = require('fs');
function handler(req) {
  const name = req.query.name;
  const p = "/data/" + name;
  return fs.readFileSync(p);
}
`)
	an, err := AnalyzeSource("t.js", src)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, fl := range an.Flows {
		if fl.Sink.Sink == SinkPath {
			found = true
		}
	}
	if !found {
		t.Errorf("未识别 JS 路径流；flows=%+v", an.Flows)
	}
}

// TestMalformedSourceNoPanic：语法错误的源码不应 panic（返回部分结果或错误）。
func TestMalformedSourceNoPanic(t *testing.T) {
	if !Available() {
		t.Skip("需 CGO 构建")
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("语法错误输入导致 panic：%v", r)
		}
	}()
	_, _ = AnalyzeSource("bad.py", []byte("def f(:\n  ???\n"))
}

// TestAnalyzePHPSQLFlow：PHP 污点链 + sink 分类（SQL）。
// PHP grammar 由 internal/astx/phpgram 第一方自持（见该包注释）。
func TestAnalyzePHPSQLFlow(t *testing.T) {
	if !Available() {
		t.Skip("需 CGO 构建")
	}
	src, err := os.ReadFile(filepath.Join("testdata", "vuln.php"))
	if err != nil {
		t.Fatal(err)
	}
	an, err := AnalyzeSource("vuln.php", src)
	if err != nil {
		t.Fatal(err)
	}
	if an.Lang != LangPHP {
		t.Fatalf("语言应识别为 php，实得 %s", an.Lang)
	}
	var found bool
	for _, fl := range an.Flows {
		if fl.Func == "handler" && fl.Sink.Sink == SinkSQL && fl.Sink.CWE == "CWE-89" {
			found = true
		}
	}
	if !found {
		t.Errorf("未识别 PHP SQL 注入流；flows=%+v", an.Flows)
	}
	for _, fl := range an.Flows {
		if fl.Func == "safe_handler" {
			t.Errorf("safe_handler 不应有数据流：%+v", fl)
		}
	}
	// 函数清单应含两个函数。
	names := map[string]bool{}
	for _, f := range an.Functions {
		names[f.Name] = true
	}
	for _, want := range []string{"handler", "safe_handler"} {
		if !names[want] {
			t.Errorf("函数清单缺少 %s（实得 %v）", want, names)
		}
	}
}
