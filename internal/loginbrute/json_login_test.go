package loginbrute

import (
	"strings"
	"testing"
)

// fakeJSONPoster JSON API 假件：admin/letmein 组合返回成功特征。
type fakeJSONPoster struct {
	bodies []string
}

func (f *fakeJSONPoster) GetSmall(rawURL string) (int, string, error) {
	return 200, `<html>login</html>`, nil
}

func (f *fakeJSONPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	return 200, "", nil
}

func (f *fakeJSONPoster) PostJSON(rawURL, body string) (int, string, error) {
	f.bodies = append(f.bodies, body)
	if strings.Contains(body, `"admin"`) && strings.Contains(body, `"letmein"`) {
		return 200, `{"msg":"login ok","token":"abc"}`, nil
	}
	return 401, `{"msg":"bad credentials"}`, nil
}

func TestJSONBruteFindsHit(t *testing.T) {
	f := &fakeJSONPoster{}
	tpl := `{"username":"{user}","password":"{pass}"}`
	hits, err := JSONBrute(f, Options{
		PageURL:      "https://x.com/api/login",
		JSONEndpoint: "https://x.com/api/login",
		JSONTemplate: tpl,
		Users:        []string{"root", "admin"},
		Passwords:    []string{"123456", "letmein"},
		MaxTries:     50,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Type != "json-api" ||
		hits[0].User != "admin" || hits[0].Password != "letmein" {
		t.Fatalf("JSON 爆破命中失败: %+v", hits)
	}
}

func TestJSONBruteTemplateRequired(t *testing.T) {
	f := &fakeJSONPoster{}
	_, err := JSONBrute(f, Options{PageURL: "https://x.com/api/login",
		Users: []string{"a"}, Passwords: []string{"b"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "JSON 模板") {
		t.Fatalf("缺模板应明确报错: %v", err)
	}
}

func TestJSONBrutePlaceholderInjection(t *testing.T) {
	// 占位符必须被替换为字典值，且模板其他部分原样保留
	f := &fakeJSONPoster{}
	_, _ = JSONBrute(f, Options{
		PageURL:      "https://x.com/api/login",
		JSONEndpoint: "https://x.com/api/login",
		JSONTemplate: `{"u":"{user}","p":"{pass}"}`,
		Users:        []string{"nobody"},
		Passwords:    []string{"nothing"},
		MaxTries:     5,
	}, nil)
	if len(f.bodies) == 0 || !strings.Contains(strings.Join(f.bodies, "|"), `"u":"nobody"`) {
		t.Fatalf("占位符未替换: %+v", f.bodies)
	}
}

func TestJSONBruteSuccessContains(t *testing.T) {
	type poster struct{ n int }
	p := &struct{ n int }{}
	_ = p
	// SuccessContains 特征命中：401 响应体含特征但状态非 200 → 不应命中
	f2 := &condPoster{want: "WELCOME"}
	opts := Options{
		PageURL:         "https://x.com/api/login",
		JSONEndpoint:    "https://x.com/api/login",
		JSONTemplate:    `{"u":"{user}","p":"{pass}"}`,
		Users:           []string{"admin"},
		Passwords:       []string{"secret"},
		SuccessContains: "WELCOME",
	}
	hits, err := JSONBrute(f2, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("成功特征应命中: %+v", hits)
	}
}

// condPoster 状态恒 200、按密码返回特征体的假件。
type condPoster struct{ want string }

func (c *condPoster) GetSmall(rawURL string) (int, string, error) {
	return 200, `<html>login</html>`, nil
}

func (c *condPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	return 200, "", nil
}

func (c *condPoster) PostJSON(rawURL, body string) (int, string, error) {
	if strings.Contains(body, "secret") {
		return 200, `{"status":"WELCOME"}`, nil
	}
	return 200, `{"status":"denied"}`, nil
}
