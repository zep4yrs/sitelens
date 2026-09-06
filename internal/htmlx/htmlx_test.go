package htmlx

import (
	"strings"
	"testing"
)

const sample = `<!doctype html><html><head>
<title>测试站首页</title>
<meta name="generator" content="WordPress 6.4">
<meta property="og:site_name" content="TS">
<script src="/wp-includes/js/jquery.min.js?ver=3.7.1"></script>
<script>var inline = 1;</script>
</head><body>
<a href="/list?page=2">列表</a>
<a href="/list?page=2">重复不收</a>
<a href="https://ext.example.com/out">外链</a>
<a href="#top">锚点</a>
<form action="/login" method="post">
  <input type="text" name="user">
  <input type="password" name="pass">
  <input type="hidden" name="csrf">
</form>
<form action="/search"><input type="text" name="q"></form>
</body></html>`

func TestParseTitleAndMetas(t *testing.T) {
	d := Parse(sample)
	if d.Title != "测试站首页" {
		t.Fatalf("title 解析失败: %q", d.Title)
	}
	if d.Metas["generator"] != "WordPress 6.4" {
		t.Fatalf("meta generator 失败: %v", d.Metas)
	}
	if d.Metas["og:site_name"] != "TS" {
		t.Fatalf("meta property 失败: %v", d.Metas)
	}
	if len(d.ScriptSrcs) != 1 || !strings.Contains(d.ScriptSrcs[0], "jquery") {
		t.Fatalf("script src 失败: %v", d.ScriptSrcs)
	}
}

func TestParseLinksDedup(t *testing.T) {
	d := Parse(sample)
	count := 0
	for _, l := range d.Links {
		if l == "/list?page=2" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("链接去重失败: %v", d.Links)
	}
	if len(d.Links) != 3 {
		t.Fatalf("链接数应为 3（列表/外链/锚点）: %v", d.Links)
	}
}

func TestParseForms(t *testing.T) {
	d := Parse(sample)
	if len(d.Forms) != 2 {
		t.Fatalf("应解析出 2 个表单: %d", len(d.Forms))
	}
	login := d.Forms[0]
	if login.Action != "/login" || login.Method != "POST" {
		t.Fatalf("登录表单解析失败: %+v", login)
	}
	if !login.HasPassword {
		t.Fatal("登录表单应含 password 框")
	}
	if len(login.Inputs) != 3 {
		t.Fatalf("登录表单应有 3 个字段: %+v", login.Inputs)
	}
	if d.Forms[1].HasPassword || d.Forms[1].Method != "GET" {
		t.Fatalf("搜索表单不应有密码且默认 GET: %+v", d.Forms[1])
	}
}

func TestAttrValueUnquoted(t *testing.T) {
	if v := attrValue(`<a href=/path/x>`, "href"); v != "/path/x" {
		t.Fatalf("无引号属性解析失败: %q", v)
	}
}
