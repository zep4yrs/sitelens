package loginbrute

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCalcEval(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"3+5", 8, true},
		{" 9 - 4 = ?", 5, true},
		{"2×6", 12, true},
		{"8/2", 4, true},
		{"abc", 0, false},
		{"7/0", 0, false},
	}
	for _, c := range cases {
		v, ok := calcEval(c.in)
		if ok != c.ok || (ok && v != c.want) {
			t.Fatalf("calcEval(%q)=%d,%v want %d", c.in, v, ok, c.want)
		}
	}
}

// 端到端：登录页带验证码图 → sidecar 识别 → 命中带验证码校验的目标。
func TestBruteWithCaptchaEndToEnd(t *testing.T) {
	// ddddocr sidecar 替身：任何图片都识别为 "8888"
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":"8888"}`)
	}))
	defer sidecar.Close()

	// 登录页：/captcha.img 返回验证码图；表单校验 captcha 字段必须为 8888
	mux := http.NewServeMux()
	mux.HandleFunc("/captcha.img", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\xff\xd8fakejpeg")
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fmt.Fprint(w, `<html><form action="/login" method="post">
				<input name="user"><input type="password" name="pass">
				<img src="/captcha.img" class="captcha-img">
				<input name="captcha"></form></html>`)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}
		if r.FormValue("captcha") != "8888" {
			w.WriteHeader(403)
			return
		}
		if r.FormValue("user") == "admin" && r.FormValue("pass") == "letmein" {
			w.WriteHeader(200)
			fmt.Fprint(w, "welcome")
			return
		}
		w.WriteHeader(403)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	users := []string{"root", "admin"}
	pwds := []string{"123456", "letmein"}
	opts := Options{
		PageURL:     srv.URL + "/login",
		Users:       users,
		Passwords:   pwds,
		MaxTries:    50,
		CaptchaType: "digits",
		OCRURL:      sidecar.URL + "/ocr",
		FetchImage: func(rawURL string) ([]byte, error) {
			resp, err := http.Get(rawURL)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)
			return buf[:n], nil
		},
	}
	hits, err := Brute(&fakeCaptchaPoster{}, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].User != "admin" || hits[0].Password != "letmein" {
		t.Fatalf("验证码爆破命中失败: %+v", hits)
	}
}

// fakeCaptchaPoster 表单提交假件：带验证码校验。
type fakeCaptchaPoster struct{ posts int }

func (f *fakeCaptchaPoster) GetSmall(rawURL string) (int, string, error) {
	return 200, `<html><form action="/login" method="post">
		<input name="user"><input type="password" name="pass">
		<img src="/captcha.img" class="captcha-img"><input name="captcha"></form></html>`, nil
}

func (f *fakeCaptchaPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	f.posts++
	if fields["user"] == "admin" && fields["pass"] == "letmein" && fields["captcha"] == "8888" {
		return 302, `<html>dashboard</html>`, nil
	}
	return 200, `<html><form action="/login"><input type="password" name="pass"></form>bad</html>`, nil
}

// PostJSON JSON 提交（Poster 接口新增方法，测试桩保持可用）。
func (f *fakeCaptchaPoster) PostJSON(rawURL, body string) (int, string, error) {
	return 200, body, nil
}

type captchaPagePoster struct{}

func (captchaPagePoster) GetSmall(string) (int, string, error) {
	return 200, `<html><form action="/l"><input type="password" name="p">
		<img src="/captcha.img" class="captcha"></form></html>`, nil
}

func (captchaPagePoster) PostJSON(string, string) (int, string, error) { return 200, "", nil }

func (captchaPagePoster) PostForm(string, map[string]string) (int, string, error) {
	return 200, "", nil
}

func TestBruteCaptchaMissingOCRErrors(t *testing.T) {
	_, err := Brute(captchaPagePoster{}, Options{PageURL: "https://x.com/l",
		Users: []string{"a"}, Passwords: []string{"b"}, CaptchaType: "digits"}, nil)
	if err == nil || !strings.Contains(err.Error(), "captcha_ocr_url") {
		t.Fatalf("有验证码字段但无 OCR 应明确报错: %v", err)
	}
}
