// 关键词区分度过滤：EHole 类社区指纹是「任一关键词命中即算」的 OR 语义，
// 而导入的关键词里混有大量通用词（login / username / must-revalidate /
// type="password" / login.php …）。只靠这类通用词命中会把一堆无关产品判为
// 命中——实测单个 DVWA 站点被判出 55~68 项技术，其中绝大多数是假阳性
// （只有 Nginx/PHP/DVWA/JQuery 等少数是真）。
//
// 修法（三层判弱，任一成立即为弱证据）：
//  1. 语义 token 全部落在 genericTokens 通用词集合内；
//  2. 唯一 token 是**过短的低熵串**（≤4 个 ASCII 字符）——`oa` / `url` /
//     `nas` / `360` / `vop` / `wso` 这类词在任意网页正文里都会出现，
//     单独命中不构成产品识别依据（实测 VOP 被判在 DVWA 上、Dahua-DSS
//     被判在 IIS 站点上，都源于此）；
//  3. 纯数字 token。
//
// 字面量通道要求至少一个**强关键词**命中才算识别（只有弱命中则不算）。
// 判定只看 token 形态，不做产品猜测——可审计、可单测。
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
	"configuration": true, "maintain": true,
	// HTML 标签 / JS 全局 / CSS 框架名：任意网页都可能出现，不构成产品识别。
	// 实测 Altoro Mutual 被判出 iframe（关键词 `<iframe`）、Haohan（Flash
	// classid）、TOPSEC（activexobject）、Swagger 三连（swagger-ui.css）。
	"iframe": true, "activexobject": true, "swagger": true, "swaggerui": true,
	"window": true, "navigator": true, "jquery": true,
	"bootstrap": true, "vue": true, "react": true, "angular": true,
	"repeat": true, "left": true, "flash": true, "swf": true,
	// 通用插件/Object 标识：Flash ActiveX classid（D27CDB6E-…）是嵌入 Flash
	// 的固定 GUID，任何带 Flash 的页面都有，不构成产品识别（实测 Altoro 被
	// 这条判成 haohan）。
	"d27cdb6e-ae6d-11cf-96b8-444553540000": true, "d27cdb6e": true,
	// HTML 标签名 / 通用 UI 缩写
	"div": true, "span": true,
	"label": true, "select": true, "option": true, "textarea": true,
	"ui": true, "ux": true, "cdn": true,
	// 下载 / 文档 / 引导类通用词（README、说明页、下载页随处可见）
	"download": true, "downloads": true, "upload": true, "install": true,
	"installer": true, "setup": true, "guide": true, "manual": true, "docs": true,
	"document": true, "documentation": true, "readme": true, "changelog": true,
	"license": true, "release": true, "note": true, "notes": true,
	"privacy": true, "policy": true, "terms": true, "faq": true,
	// 文件后缀（login.php / login.css 里的 php/css 是扩展名，不携带产品信息）
	"php": true, "asp": true, "aspx": true, "jsp": true, "do": true,
	"aspnet": true, "cgi": true, "py": true, "rb": true, "pl": true, "sh": true,
	"xhtml": true, "txt": true, "bak": true,
	// 网页里高频出现、无产品区分度的短词（实测 EHole 导入关键词里混入这些，
	// 单独命中会把无关产品判成命中：Dahua-DSS 靠 "url"、Jiusi-OA 靠 "oa"、
	// 35Mail 靠 "35"、VOP 靠 "vop" 全被判在 DVWA/IIS 站点上）
	"url": true, "uri": true, "href": true, "src": true, "id": true,
	"host": true, "http": true, "https": true, "www": true, "location": true,
	"redirect": true, "refresh": true, "modules": true, "plugins": true,
	"theme": true, "tmp": true, "temp": true, "data": true, "file": true,
	"folder": true, "dir": true, "path": true, "list": true, "view": true,
	"show": true, "edit": true, "add": true, "del": true, "delete": true,
	"update": true, "save": true, "load": true, "open": true,
	"click": true, "send": true, "get": true, "post": true,
	"put": true, "head": true, "meta": true, "base": true, "frame": true,
	"table": true, "class": true, "width": true,
	"height": true, "color": true, "font": true, "size": true, "align": true,
	"center": true, "border": true, "background": true, "position": true,
	"display": true, "margin": true, "padding": true, "float": true,
	"nas": true, "san": true, "dns": true, "ftp": true, "ssh": true, "smtp": true,
	"pop": true, "imap": true, "ldap": true, "ssl": true, "tls": true,
	"vpn": true, "utm": true, "waf": true, "ids": true, "ips": true,
	"oa": true, "erp": true, "crm": true, "cms": true, "bbs": true, "blog": true,
	"vop": true, "voip": true, "vo": true, "vps": true, "isp": true, "idc": true,
	"mail": true, "webmail": true, "exchange": true, "sessid": true,
	"session": true, "sess": true, "sid": true, "token": true, "csrf": true,
	"nonce": true, "hash": true, "key": true, "secret": true,
	"itc": true, "wcm": true, "dss": true, "hfs": true, "aten": true, "tps": true,
	"plc": true, "scada": true, "hmi": true, "cctv": true, "nvr": true, "dvr": true,
	"router": true, "switch": true, "gateway": true, "firewall": true,
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

// minStrongTokenLen ASCII 强 token 的最小长度：短于此长度的纯 ASCII token
// 在网页里几乎必然出现（ur l / oa / n as / 3 6 0 / wso…），单独命中不足以
// 识别产品。5 是实测调出的下界——`dvwa`(4) 这类短英文产品名确实存在，但
// 它们总伴随后续高熵关键词（dvwa/css/login.css）或有正则通道，不走此闸。
const minStrongTokenLen = 5

// tokenLowEntropy 判断单个 token 是否为低熵（不承载产品信息）。
func tokenLowEntropy(t string) bool {
	if t == "" {
		return true
	}
	// 纯数字：360 / 8000 / 2000 类端口与型号数字遍地都是
	allDigit := true
	for _, r := range t {
		if r < '0' || r > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		return true
	}
	// 纯 ASCII 且短于下界：oa / url / nas / dss / wcm / hfs / vop…
	ascii := true
	for _, r := range t {
		if r > 127 {
			ascii = false
			break
		}
	}
	if ascii && len(t) < minStrongTokenLen {
		return true
	}
	return false
}

// weakKeyword 判断字面量关键词是否为「弱证据」：其**全部**语义 token 都是
// 通用词、或全部都是低熵短串时成立。
//
// 返回 true 表示该关键词区分度不足，不能单独作为识别依据。
// 无有效 token（纯符号）也视为弱。
//
// 「有结构」的关键词（含路径 / 引号 / 等号 / 连字符复合词）本身携带上下文，
// 走宽松判定：只要存在非通用 token 即为强证据——`dvwa/css/login.css` 里的
// `dvwa` 虽短，但「dvwa 目录下的 login.css」是强上下文，不该被短词闸门误杀。
// 只有**裸 token 关键词**（无任何结构）才受低熵短串闸门约束。
func weakKeyword(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	// 通用插件/Object 标识（Flash ActiveX classid GUID 等）：整串判弱。
	// 这类固定常量在任何嵌入 Flash 的页面上都出现，不携带产品信息。
	if isGenericPluginID(trimmed) {
		return true
	}
	tokens := tokenizeKeyword(strings.ToLower(trimmed))
	if len(tokens) == 0 {
		return true
	}
	structured := hasKeywordStructure(trimmed)
	for _, t := range tokens {
		if genericTokens[t] {
			continue // 通用词：不贡献区分度
		}
		if !structured && tokenLowEntropy(t) {
			continue // 裸关键词里的低熵短串 / 纯数字：不贡献区分度
		}
		return false // 存在非通用 token → 强证据
	}
	return true
}

// hasKeywordStructure 判断关键词是否带上下文结构（路径 / 复合词 / 等号赋值
// 等）——这类关键词的短 token 仍具区分度。
//
// 注意：**标签/引号结构不算**。`<iframe` / `window.location` / `type="password"`
// 这类片段是 HTML/JS 通用构件，任意页面都有，带上它也说明不了是什么产品；
// 只有路径（`dvwa/css/login.css`）、复合词（`switchingserverpopup`）、
// 等号赋值（`name="dkey_login"`）这类才真正携带产品上下文。
func hasKeywordStructure(s string) bool {
	if strings.ContainsAny(s, "/\\") {
		return true
	}
	if strings.ContainsAny(s, "-_") {
		return true
	}
	if strings.Contains(s, "=") {
		return true
	}
	if strings.Contains(s, ".") {
		return true
	}
	return false
}

// productNameOnly 判断强关键词是否只是**裸产品名形态**（低上下文区分度）。
//
// 产品名（VMware / Consul / MacOS / Apache）单独出现在页面里，无法证明该页面
// 或站点就是此产品——它可能是 README 的部署选项列表、下载页、讨论贴、对比表格。
// 实测 DVWA 首页 README 提到一次 "VMware" 就判出 VMware Horizon/vCenter/
// vRealize 三项技术。相对地，带路径（dvwa/images/logo.png）、域名
// （help.mail.35.com）、版本号（nginx/1.31.6）、连字符复合词
// （switchingserverpopup）的关键词天然带上下文，不属此类。
//
// 返回 true 表示该关键词需要同一指纹的第二个关键词佐证。
func productNameOnly(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	// 含路径 / 查询 / 域名分隔符：有上下文
	if strings.ContainsAny(s, "/\\.=?:&%<>\"'()[]{}") {
		return false
	}
	// 含连字符/下划线复合词：有上下文
	if strings.ContainsAny(s, "-_") {
		return false
	}
	// 含版本号数字：有上下文
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return false
		}
	}
	// 含引号 / 尖括号 / 等号：是标签片段而非裸词，有上下文
	if strings.ContainsAny(s, "\"'<>[]()") {
		return false
	}
	tokens := tokenizeKeyword(s)
	if len(tokens) != 1 {
		return false // 多词（两个实词）已是复合描述，有上下文
	}
	t := tokens[0]
	if len(t) < 5 {
		return false // 短词走低熵闸门，不走此路
	}
	// 长单词（≥13 字母）几乎必是产品自造的复合串（switchingserverpopup /
	// dahuadefined / lgform），区分度足够，不属裸产品名
	if len(t) >= 13 {
		return false
	}
	// 纯 ASCII 单词 / 单段 CJK：裸产品名形态
	for _, r := range t {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r > 127) {
			return false
		}
	}
	return true
}

// appendUnique 去重追加（保持顺序）。用于收集同一指纹命中的多个关键词。
func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// genericPluginIDs 通用插件 / Object 嵌入标识（小写、去分隔符后比对）。
// 这些是浏览器插件的固定 GUID，不指向任何具体产品。
var genericPluginIDs = map[string]bool{
	"d27cdb6eae6d11cf96b8444553540000":     true, // Flash ActiveX classid
	"0002e51000000000c000000000000046":     true, // Microsoft Office Web Components
	"02bf25d5-8c17-4b23-bc80-d3488abddc6b": true, // QuickTime
}

// isGenericPluginID 判断关键词是否为通用插件标识（大小写/分隔符不敏感）。
func isGenericPluginID(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if genericPluginIDs[s] {
		return true
	}
	// 去掉 - / . 分隔符后再比对（GUID 有多种书写形态）
	norm := ""
	for _, r := range s {
		if r == '-' || r == '.' || r == '/' {
			continue
		}
		norm += string(r)
	}
	return genericPluginIDs[norm]
}
