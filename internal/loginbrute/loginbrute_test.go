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

func (f *fakePoster) PostJSON(rawURL, body string) (int, string, error) {
	return f.PostForm(rawURL, map[string]string{"__raw__": body})
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

	hits, err := Brute(f, Options{PageURL: "https://x.com/login", Users: users,
		Passwords: pwds, MaxTries: 400}, nil)
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
	_, err := Brute(p, Options{PageURL: "https://x.com/", Users: []string{"a"},
		Passwords: []string{"b"}, MaxTries: 10}, nil)
	if err == nil || !strings.Contains(err.Error(), "未解析到") {
		t.Fatalf("无表单应报诊断错误: %v", err)
	}
}

type noFormPoster struct{}

func (n *noFormPoster) GetSmall(string) (int, string, error) {
	return 200, "<html>no form here</html>", nil
}
func (n *noFormPoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (n *noFormPoster) PostForm(string, map[string]string) (int, string, error) {
	return 200, "", nil
}

func TestBruteCaptchaRefused(t *testing.T) {
	_, err := Brute(&fakePoster{}, Options{PageURL: "https://x.com/login",
		Users: []string{"a"}, Passwords: []string{"b"}, MaxTries: 10,
		CaptchaType: "digits"}, nil)
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
	if form.PassField != "请输入密码" {
		// 与 Python 宽容版一致：name/id 缺失时用 placeholder 作为提交字段名
		t.Fatalf("密码字段应取 placeholder: %q", form.PassField)
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

// dvwaPoster 模拟 DVWA 登录行为：成功 302 + 空正文，失败 200 + 登录页。
type dvwaPoster struct{ posts int }

func (f *dvwaPoster) GetSmall(rawURL string) (int, string, error) {
	return 200, `<html><form action="login.php" method="post">
<input type="text" name="username"><input type="password" name="password">
<input type="hidden" name="user_token" value="t"><input type="submit" name="Login" value="Login"></form></html>`, nil
}

func (f *dvwaPoster) PostJSON(rawURL, body string) (int, string, error) {
	return f.PostForm(rawURL, map[string]string{"__raw__": body})
}

func (f *dvwaPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	f.posts++
	if fields["username"] == "admin" && fields["password"] == "password" {
		return 302, "", nil // 成功：重定向 + 空正文（DVWA 真实行为）
	}
	return 200, `<html><div class="message">Login failed</div>
<form action="login.php" method="post"><input type="password" name="password"></form></html>`, nil
}

func TestBruteDVWA302Success(t *testing.T) {
	f := &dvwaPoster{}
	hits, err := Brute(f, Options{PageURL: "http://dvwa/login.php",
		Users: []string{"admin"}, Passwords: []string{"password"}, MaxTries: 10}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].User != "admin" {
		t.Fatalf("DVWA 302 成功应命中: %+v", hits)
	}
}

func TestBruteComboBudgetRespected(t *testing.T) {
	// 组合总数必须严格受 MaxTries 约束：3 用户 × 3 口令 = 9 组合，
	// MaxTries=4 → 最多 3 次尝试 + 1 次基线 = 4 次提交
	f := &dvwaPoster{}
	_, err := Brute(f, Options{PageURL: "http://dvwa/login.php",
		Users: []string{"a", "b", "c"}, Passwords: []string{"1", "2", "3"}, MaxTries: 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.posts > 4 {
		t.Fatalf("MaxTries=4 应最多 4 次提交，实际 %d", f.posts)
	}
}

func TestIsSuccessRedirectToLoginRejected(t *testing.T) {
	// 302 但正文提示跳回登录页：不算命中
	body := `<html><script>location.href="login.php?error=1"</script></html>`
	if isSuccess(302, body, 200, 500) {
		t.Fatal("跳回登录页不应判定成功")
	}
	// 302 空正文：命中
	if !isSuccess(302, "", 200, 500) {
		t.Fatal("302 空正文应判定成功")
	}
	// 200 且含密码框：不命中
	if isSuccess(200, `<input type="password">`, 200, 500) {
		t.Fatal("仍含密码框不应判定成功")
	}
}
