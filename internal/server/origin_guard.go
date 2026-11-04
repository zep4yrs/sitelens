// BL-1 / V-05：浏览器来源闸（Host 白名单 + CSRF 防护）。
//
// 背景：本服务默认 web.auth_mode=none 且 api_token 为空（config.Default），
// 监听 127.0.0.1。默认无认证本身可接受（仅本机），但**没有 Host/Origin 校验**
// 时，任意网页可用 DNS rebinding 把自有域名解析到 127.0.0.1，让浏览器以
// 同源身份读写全部 API；同时浏览器"简单请求"（form POST / text-plain JSON）
// 不触发 CORS 预检，可跨站触发写操作（CSRF）。
//
// 本中间件做四件事（顺序即先便宜后昂贵）：
//  1. Host 白名单：回环监听时只接受回环 Host（127.0.0.1/localhost/[::1]…），
//     非回环监听（显式对外）时不做主机名限制，交由 2/3 兜底；
//  2. Sec-Fetch-Site: cross-site → 拒绝（现代浏览器跨站请求必带）；
//  3. 有 Origin / Referer 时必须与请求 Host 同源；
//  4. POST 的请求体类型必须是 JSON（或白名单 multipart / 显式 CSRF 头）——
//     application/json 属 CORS 非简单类型，跨站 JS 必须预检，而本服务
//     不发 CORS 允许头，因此天然拦住跨站写。
//
// 为什么只对 POST 要求 Content-Type：浏览器表单只能提交 GET/POST；PUT/
// DELETE/PATCH 跨站必须预检，本身无法构成 CSRF。把 PUT/DELETE 也纳入
// 类型检查只会误伤 curl/CLI（如 DELETE 无 body），不增加安全性。
package server

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	// csrfHeader 危险端点的显式自定义头（跨站 JS 无法在不触发预检的情况下
	// 携带自定义头；表单更不可能）。值固定，便于客户端实现。
	csrfHeader      = "X-Requested-With"
	csrfHeaderValue = "sitelens"
	// jsonMediaType POST 唯一放行的结构化请求体类型。
	jsonMediaType = "application/json"
	// formUploadPath 仅此端点接受 multipart/form-data（源码审计上传）。
	formUploadPath = "/api/audit"
	// devSPATargetLoginPath 内置 SPA 靶页登录端点（配置开关打开时才注册）。
	devSPATargetLoginPath = "/dev/spa-target/login"
)

// dangerousEndpoint 需要"显式来源证据"的破坏性/配置类端点。
// 现在的判定：自定义头或 JSON Content-Type 二者其一（"或等价 CSRF token"），
// 因为现有 SPA 的 api.post/put 全部走 JSON 且不会自动加自定义头；
// F6 在 web/js/common.js 的 tok() 里统一补 csrfHeader 后，可把
// requireCSRFHeaderStrict 置 true 收紧为"必须带头"。
func dangerousEndpoint(method, path string) bool {
	switch {
	case method == http.MethodPost && path == "/api/history/clear":
		return true
	case strings.HasPrefix(path, "/api/admin/"):
		return true
	case method == http.MethodPut && path == "/api/settings":
		return true
	case strings.HasPrefix(path, "/api/batch/schedules"):
		return true
	}
	return false
}

// requireCSRFHeaderStrict=true 时危险端点必须带 csrfHeader（默认 false：与
// JSON Content-Type 二选一，避免在 F6 补头之前打断设置页/任务看板）。
var requireCSRFHeaderStrict = false

// originGuard 浏览器来源闸。必须挂在 guard 之外（认证之前）：Host/来源在
// 任何凭据之前就应判定，且能覆盖 none 模式的"无凭据"路径。
func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1) Host 白名单（DNS rebinding 主闸）。
		if !s.hostAllowed(r.Host) {
			guardDeny(w, r, "Host 不被允许（仅接受本机回环地址访问）")
			return
		}
		// 2) 浏览器显式声明跨站：直接拒。
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
			guardDeny(w, r, "拒绝跨站请求（Sec-Fetch-Site: cross-site）")
			return
		}
		// 3) Origin / Referer 同源校验（老浏览器没有 Sec-Fetch-Site）。
		if !sameOriginRequest(r) {
			guardDeny(w, r, "Origin/Referer 与请求 Host 不同源")
			return
		}
		// 4) 写请求体类型（CSRF 主闸）。
		if r.Method == http.MethodPost && !s.postBodyAllowed(r) {
			// 415 而非 403：语义上这是"媒体类型不被接受"，也让既有测试里
			// "写接口不应 401/403" 的断言继续成立（拒绝理由不同）。
			guardDenyStatus(w, r, http.StatusUnsupportedMediaType,
				"POST 需 Content-Type: application/json（或 X-Requested-With: sitelens）")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guardDeny 统一拒绝响应（403）。
func guardDeny(w http.ResponseWriter, r *http.Request, reason string) {
	guardDenyStatus(w, r, http.StatusForbidden, reason)
}

// guardDenyStatus 带状态码的拒绝响应（JSON，带可操作提示；不泄露内部细节）。
func guardDenyStatus(w http.ResponseWriter, r *http.Request, status int, reason string) {
	log.Printf("来源闸拒绝 %s %s（Host=%q Origin=%q）：%s",
		r.Method, r.URL.Path, r.Host, r.Header.Get("Origin"), reason)
	writeJSON(w, status, map[string]any{"error": reason})
}

// hostAllowed 回环监听时只接受回环 Host；非回环监听时不做主机名限制。
//
// 只比主机名不比端口：DNS rebinding 的 Host 是攻击者域名（必然非回环），
// 拦主机名即可；而测试/桌面壳端口在运行期才确定（desktop-wails 选空闲端口
// 后写 web.listen，httptest 更是随机端口），强制端口相等会把合法访问挡掉。
func (s *Server) hostAllowed(hostport string) bool {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	host := requestHostname(hostport)
	if host == "" {
		return false
	}
	listenAddr := ""
	if s != nil && cfg != nil {
		listenAddr = strings.TrimSpace(cfg.Web.Listen)
	}
	listenHost := listenAddr
	if h, _, err := net.SplitHostPort(listenAddr); err == nil {
		listenHost = h
	}
	// 空 listen（测试零值）按回环处理（安全默认）。
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	if !isLoopbackHost(listenHost) {
		// 显式对外监听：主机名无法枚举（0.0.0.0/域名反代），放行任意 Host，
		// 由 Sec-Fetch-Site / Origin 同源规则兜底。
		return true
	}
	return isLoopbackHost(host)
}

// isLoopbackHost 主机名是否本机回环（localhost / 127.0.0.0/8 / ::1）。
func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if i := strings.IndexByte(host, '%'); i >= 0 { // IPv6 zone：fe80::1%eth0
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requestHostname 取 Host 头里的主机名（兼容 IPv6 字面量与无端口形态）。
func requestHostname(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]")
	}
	// 无端口：可能是 "127.0.0.1"、"::1"、"[::1]"、域名。
	return strings.Trim(hostport, "[]")
}

// sameOriginRequest 有 Origin/Referer 时必须与请求 Host 同源；都没有则放行
// （curl/CLI/MCP 等非浏览器客户端不带这些头）。
//
// 只比 host:port 不比 scheme：桌面 WebView（wails）可能以 https 拦截/http
// 实际转发，要求 scheme 严格相等会误伤；而 Host 一致性已足以阻断跨站来源。
func sameOriginRequest(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return originMatchesHost(origin, r.Host)
	}
	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		return originMatchesHost(ref, r.Host)
	}
	return true
}

// originMatchesHost 解析 Origin/Referer 并与请求 Host 比较（大小写不敏感）。
// "null"（file:// / sandboxed iframe）与解析失败一律不同源。
func originMatchesHost(raw, host string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// postBodyAllowed POST 请求体类型白名单。
//
// 顺序（任一命中即放行）：
//  1. 携带显式凭据头（X-Token / Authorization）——浏览器不会自动附加这两种
//     头，跨站 JS 携带又必须预检，故不可能是 CSRF；CLI/测试/桌面壳走这条。
//  2. 危险端点：要求 JSON 或 CSRF 头（multipart 白名单对危险端点不生效）。
//  3. JSON。
//  4. 显式 CSRF 头。
//  5. 表单类白名单路径（/api/audit 上传、开开关后的 /dev/spa-target/login）。
func (s *Server) postBodyAllowed(r *http.Request) bool {
	if hasCredentialHeader(r) {
		return true
	}
	ct := mediaTypeOf(r.Header.Get("Content-Type"))
	headerOK := strings.EqualFold(strings.TrimSpace(r.Header.Get(csrfHeader)), csrfHeaderValue)
	jsonOK := ct == jsonMediaType

	if dangerousEndpoint(r.Method, r.URL.Path) {
		if requireCSRFHeaderStrict {
			return headerOK
		}
		return jsonOK || headerOK
	}
	if jsonOK || headerOK {
		return true
	}
	// 表单类白名单：/api/audit（前端 audit.js 用 FormData 上传源码包）；
	// /dev/spa-target/login（仅当开发靶页开关打开时才注册，见 Handler）。
	isForm := ct == "multipart/form-data" || ct == "application/x-www-form-urlencoded"
	if !isForm {
		return false
	}
	path := r.URL.Path
	if path == formUploadPath {
		return true
	}
	return path == devSPATargetLoginPath && devSPATargetEnabled()
}

// mediaTypeOf 取 Content-Type 的 media type（去参数、小写）。
func mediaTypeOf(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// hasCredentialHeader 是否携带显式 API 凭据头（X-Token / Bearer）。
func hasCredentialHeader(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-Token")) != "" {
		return true
	}
	return strings.TrimSpace(r.Header.Get("Authorization")) != ""
}

// devSPATargetEnabled 内置 SPA 靶页开关（V-18）：默认关，显式置 1/true/yes/on 才注册。
//
// 该靶页含硬编码演示凭据（admin/admin123），只应出现在自测/演示环境；
// 生产/桌面壳默认关闭，避免"测试后门"混入产品面。
func devSPATargetEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SITELENS_DEV_SPA_TARGET"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
