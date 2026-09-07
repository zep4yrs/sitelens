// 内置 SPA 靶页：JS 延迟注入登录表单 + 校验端点。
// 用途：无头渲染链路与登录爆破的自测靶子（curl/工具均可打）。
// 表单由 JS 在 DOMContentLoaded 后 300ms 注入——静态 HTML 中没有表单，
// 只有渲染后才能看到，正好检验 chromedp/无头渲染链路。
package server

import (
	"net/http"
)

const spaTargetPage = `<!doctype html><html><body><div id="app">loading</div><script>
setTimeout(function(){
  document.getElementById("app").innerHTML =
    '<form action="/dev/spa-target/login" method="post">' +
    '<input name="user"><input type="password" name="pass"></form>';
}, 300);
</script></body></html>`

func hSPATarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(spaTargetPage))
}

// hSPATargetLogin 校验演示凭据 admin/admin123：命中返回 200 欢迎页，
// 否则 403（表单爆破的失败基线判定依赖这一差异）。
func hSPATargetLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		return
	}
	if r.FormValue("user") == "admin" && r.FormValue("pass") == "admin123" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>welcome dashboard</html>"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(403)
	_, _ = w.Write([]byte("<html>denied</html>"))
}
