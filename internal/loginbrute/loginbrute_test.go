package loginbrute

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/htmlx"
)

// fakePoster 表单提交假件：特定凭据命中，其余统一失败页。
type fakePoster struct {
	hitUser, hitPass string
	posts            int
}

func (f *fakePoster) GetSmall(rawURL string) (int, string, error) {
	return 200, `<html><form action="/login" method="post">
<input name="user"><input type="password" name="pass"></form></html>`, nil
}

func (f *fakePoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	f.posts++
	if fields["user"] == f.hitUser && fields["pass"] == f.hitPass {
		return 302, `<html>redirect to /dashboard</html>`, nil
	}
	return 200, `<html><form action="/login"><input type="password" name="pass"></form>login failed</html>`, nil
}

func TestBruteFindsHit(t *testing.T) {
	f := &fakePoster{hitUser: "admin", hitPass: "letmein"}
	users := LoadList("../../data/wordlists/weak_users.txt", 8)
	pwds := LoadList("../../data/wordlists/weak_passwords.txt", 50)
	if len(users) == 0 || len(pwds) == 0 {
		t.Skip("字典文件缺失")
	}
	// 保证命中组合在截取范围内
	users = append([]string{"admin"}, users...)
	pwds = append([]string{"letmein"}, pwds...)

	hits, err := Brute(f, "https://x.com/login", users, pwds, 400, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].User != "admin" || hits[0].Password != "letmein" {
		t.Fatalf("命中失败: %+v", hits)
	}
	if f.posts < 2 {
		t.Fatal("应至少有基线+尝试两次提交")
	}
}

func TestBruteNoForm(t *testing.T) {
	p := &noFormPoster{}
	_, err := Brute(p, "https://x.com/", []string{"a"}, []string{"b"}, 10, "", nil)
	if err == nil || !strings.Contains(err.Error(), "未解析到") {
		t.Fatalf("无表单应报诊断错误: %v", err)
	}
}

type noFormPoster struct{}

func (n *noFormPoster) GetSmall(string) (int, string, error) {
	return 200, "<html>no form here</html>", nil
}
func (n *noFormPoster) PostForm(string, map[string]string) (int, string, error) {
	return 200, "", nil
}

func TestBruteCaptchaRefused(t *testing.T) {
	_, err := Brute(&fakePoster{}, "https://x.com/login",
		[]string{"a"}, []string{"b"}, 10, "digits", nil)
	if err == nil || !strings.Contains(err.Error(), "验证码") {
		t.Fatalf("验证码能力缺失应明确报错: %v", err)
	}
}

func TestAnalyzeInferFields(t *testing.T) {
	page := `<html><form action="/signin" method="post">
	<input type="text" id="account" placeholder="邮箱/账号">
	<input type="hidden" name="csrf" value="tok123">
	<input type="password" placeholder="请输入密码">
	</form></html>`
	// 用 htmlx 解析后 analyze 应推断出字段
	doc := htmlx.Parse(page)
	form, _ := AnalyzeWithDiag(doc, "https://x.com/login")
	if form == nil {
		t.Fatal("应解析出表单")
	}
	if form.UserField != "account" {
		t.Fatalf("用户字段推断失败: %q", form.UserField)
	}
	if form.PassField != "password" {
		t.Fatalf("密码字段缺名时应回退默认: %q", form.PassField)
	}
	if form.Hidden["csrf"] != "tok123" {
		t.Fatalf("隐藏字段丢失: %+v", form.Hidden)
	}
}

func TestIsSuccessBaseline(t *testing.T) {
	if isSuccess(200, strings.Repeat("a", 1000), 200, 1000) {
		t.Fatal("与基线一致不应命中")
	}
	if !isSuccess(200, strings.Repeat("a", 5000), 200, 1000) {
		t.Fatal("显著偏离基线应命中")
	}
	if isSuccess(403, "x", 200, 1000) {
		t.Fatal("4xx 不应命中")
	}
}
