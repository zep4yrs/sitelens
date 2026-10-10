package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestCaptchaAuthzAPICryptoEndToEnd 端到端：模拟靶场同时含四类缺陷
// （验证码校验缺失 / 越权 / API 未授权+IDOR / 确定性加密），
// 验证四条新通道都能从扫描结果里落地。
func TestCaptchaAuthzAPICryptoEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/":
			// 首页同时列出表单（表单采集走首页 + 爬取页两条路）
			w.Write([]byte(`<html><body>
<a href="/profile?user_id=1">p</a><a href="/api/v2/user/1">a</a>
<a href="/captcha">c</a><a href="/crypto">k</a>
<form method="post" action="/crypto"><input name="text"><input type="submit"></form>
<form method="post" action="/captcha"><input name="user"><input name="captcha"><input type="submit"></form>
</body></html>`))
		case p == "/profile":
			uid := r.URL.Query().Get("user_id")
			if uid == "" {
				uid = "1"
			}
			w.Write([]byte("<html>profile of " + uid + strings.Repeat("x", 200+80*len(uid)) + "</html>"))
		case strings.HasPrefix(p, "/api/v2/user/"):
			uid := p[strings.LastIndex(p, "/")+1:]
			body := map[string]any{"id": uid, "password_hash": "abc123", "email": "u" + uid + "@x.com"}
			if uid == "2" {
				body["orders"] = strings.Repeat("z", 300)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		case p == "/captcha":
			if r.Method == http.MethodPost {
				w.Write([]byte(`<div class="success">Captcha was correct</div>`))
				return
			}
			w.Write([]byte(`<html><form method="post" action="/captcha">
<input name="user"><input name="captcha"><input type="submit"></form></html>`))
		case p == "/crypto":
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				plain := r.FormValue("text")
				// 确定性加密：同一明文同一密文（模拟 ECB / 固定 IV）。
				// 用十六进制形态——密文识别要求定长可辨识串，随机文本不认。
				var b strings.Builder
				for i := 0; i < 32; i++ {
					v := 0
					if i < len(plain) {
						v = int(plain[i])
					}
					fmt.Fprintf(&b, "%x", (v+i)%16)
				}
				w.Write([]byte("<html>cipher: " + b.String() + "</html>"))
				return
			}
			w.Write([]byte(`<html><form method="post" action="/crypto">
<input name="text"><input type="submit"></form></html>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/", Options{Deep: true, DAST: true}, nil, nil)

	want := map[string]bool{
		"captcha-missing":      false,
		"authz-bypass":         false,
		"api-unauth":           false,
		"api-idor":             false,
		"crypto-deterministic": false,
	}
	for _, v := range res.Verified {
		if c, ok := v["check"].(string); ok {
			if _, tracked := want[c]; tracked {
				want[c] = true
			}
		}
	}
	for c, ok := range want {
		if !ok {
			t.Errorf("应命中 %s 但未出现在 verified", c)
		}
	}
}

// TestCaptchaAuthzAPICryptoSafeSite 安全站：受保护 API / 正常校验验证码 /
// 随机 IV 加密 / 访问控制生效的标识，四条通道都不得产出发现。
func TestCaptchaAuthzAPICryptoSafeSite(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/":
			w.Write([]byte(`<html><body>
<a href="/api/v2/user/1">a</a><a href="/captcha">c</a></body></html>`))
		case strings.HasPrefix(p, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthorized"}`))
		case p == "/captcha":
			if r.Method == http.MethodPost {
				w.Write([]byte(`<div class="error">Incorrect captcha, try again</div>`))
				return
			}
			w.Write([]byte(`<html><form method="post" action="/captcha">
<input name="user"><input name="captcha"><input type="submit"></form></html>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	_ = n

	cfg := config.Default()
	cfg.Scan.RateIntervalMS = 0
	cfg.Target.AllowPrivate = true
	eng := New(cfg, nil, nil)
	res := eng.Scan(srv.URL+"/", Options{Deep: true, DAST: true}, nil, nil)

	for _, v := range res.Verified {
		c, _ := v["check"].(string)
		switch c {
		case "captcha-missing", "authz-bypass", "api-unauth", "api-idor",
			"crypto-deterministic", "crypto-weak-algo", "captcha-replay":
			t.Errorf("安全站不得产出 %s: %+v", c, v)
		}
	}
}
