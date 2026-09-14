// 关键词区分度过滤：EHole 类社区指纹是「任一关键词命中即算」的 OR 语义，
// 而导入的关键词里混有大量通用词（login / username / must-revalidate /
// type="password" / login.php …）。只靠这类通用词命中会把一堆无关产品判为
// 命中——实测单个 DVWA 站点被判出 58 项技术，其中 54 项是假阳性
// （只有 Apache/PHP/Debian/DVWA 是真）。
//
// 修法：把「全部语义 token 都是通用词」的字面量关键词判为**弱证据**；
// 字面量通道要求至少一个**强关键词**命中才算识别（只有弱命中则不算）。
// 判定只看 token 是否全为通用词，不做长度/正则猜测——可审计、可单测。
//
// 范围：只作用于字面量（EHole 导入的关键词）通道；Wappalyzer 风格的正则
// 模式是人工精编的、天然有区分度，不受影响。
package sitelens

import "strings"

// genericTokens 通用词集合（小写）。判定为「弱证据」的关键词，其**所有** token
// 都必须落在此集合内。宁可集合偏大——因为规则是「全部 token 通用才弱」，
// 只要有一个 token 不在集合里就仍算强证据，故偏大不会误杀真指纹。
var genericTokens = map[string]bool{
	// 认证 / UI 通用词
	"login": true, "log": true, "logout": true, "signin": true, "sign": true,
	"signup": true, "register": true, "username": true, "user": true, "name": true,
	"password": true, "passwd": true, "pass": true, "pwd": true, "admin": true,
	"submit": true, "button": true, "form": true, "input": true, "field": true,
	"email": true, "search": true, "query": true, "captcha": true, "verify": true,
	"account": true, "auth": true, "credential": true, "remember": true, "forgot": true,
	// 页面 / 结构通用词
	"index": true, "home": true, "main": true, "page": true, "content": true,
	"title": true, "body": true, "text": true, "string": true, "value": true,
	"default": true, "header": true, "footer": true, "nav": true, "menu": true,
	"tab": true, "panel": true, "container": true, "wrapper": true, "layout": true,
	// 技术 / 资源通用词
	"html": true, "htm": true, "css": true, "js": true, "json": true, "xml": true,
	"png": true, "jpg": true,
	"jpeg": true, "gif": true, "svg": true, "ico": true, "woff": true, "web": true,
	"image": true, "img": true, "logo": true, "icon": true, "style": true,
	"script": true, "link": true, "dom": true, "app": true, "application": true,
	"site": true, "server": true, "client": true, "service": true, "system": true,
	"interface": true, "userinterface": true, "framework": true, "platform": true,
	// 管理 / 门户通用词
	"manage": true, "management": true, "manager": true, "console": true,
	"portal": true, "paneladmin": true, "dashboard": true, "backend": true,
	"control": true, "config": true, "setting": true, "settings": true,
	"tool": true, "tools": true, "util": true, "utility": true, "help": true,
	"about": true, "contact": true, "support": true, "welcome": true,
	// HTTP / 缓存通用词（wildcard 头通道常见）
	"powered": true, "by": true, "must": true, "revalidate": true, "no": true,
	"cache": true, "store": true, "max": true, "age": true, "public": true,
	"private": true, "proxy": true, "expires": true, "pragma": true, "etag": true,
	"keep": true, "alive": true, "close": true, "chunked": true, "gzip": true,
	"utf": true, "charset": true, "type": true, "encoding": true, "language": true,
	// 调试 / 演示通用词
	"test": true, "demo": true, "sample": true, "example": true, "dev": true,
	"debug": true, "ok": true, "success": true, "error": true, "warning": true,
	"info": true, "new": true, "old": true, "version": true, "copyright": true,
	// 文件后缀（login.php / login.css 里的 php/css 是扩展名，不携带产品信息）
	"php": true, "asp": true, "aspx": true, "jsp": true, "do": true,
	"aspnet": true, "cgi": true, "py": true, "rb": true, "pl": true, "sh": true,
	"xhtml": true, "txt": true, "bak": true,
	// 中文通用词
	"登录": true, "登陆": true, "系统": true, "管理": true, "后台": true,
	"首页": true, "主页": true, "用户名": true, "密码": true, "用户": true,
	"平台": true, "服务": true, "平台系统": true, "管理中心": true, "控制台": true,
	"信息": true, "网络": true, "安全": true, "网关": true, "路由器": true,
}

// tokenizeKeyword 把关键词拆为语义 token：连续的 ASCII 字母数字、或连续的
// 非 ASCII（含 CJK）各成一段；其余字符（标点 / 引号 / 路径分隔符）视为分隔。
// 例：`dvwa/css/login.css` → [dvwa, css, login, css]
func tokenizeKeyword(s string) []string {
	s = strings.ToLower(s) // 统一小写：大写字母不应被视为分隔符
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			cur.WriteRune(r)
		case r > 127:
			cur.WriteRune(r) // CJK 等：连续非 ASCII 归一段
		default:
			flush() // 标点 / 分隔符
		}
	}
	flush()
	return out
}

// weakKeyword 判断字面量关键词是否为「弱证据」：其全部语义 token 都是通用词。
//
// 返回 true 表示该关键词区分度不足，不能单独作为识别依据。
// 无有效 token（纯符号）也视为弱。
func weakKeyword(raw string) bool {
	tokens := tokenizeKeyword(strings.ToLower(strings.TrimSpace(raw)))
	if len(tokens) == 0 {
		return true
	}
	for _, t := range tokens {
		if !genericTokens[t] {
			return false // 存在非通用 token → 强证据
		}
	}
	return true
}
