// URL 输入归一化（自动修正）：把用户从聊天框/报告/工单里粘来的脏地址
// 变成可扫描的合法 URL。
//
// 设计红线（与产品「可复核 / 不改目标」一致）：
//   - 只改格式，不改目标：不猜域名、不做 typo 纠正、不切 www/apex、
//     不跨域跳转、不降级协议、不猜端口、不做路径穿越归一化；
//   - 纯函数：不解析 DNS、不发请求，可在测试里逐条断言；
//   - 幂等：Normalize(Normalize(x).URL) 不再产生 changes；
//   - 修正必留痕：调用方把 Changes 写入结果 extras / 预检字段 / 前端提示。
//
// 覆盖的脏输入形态：缺协议、hxxp/[.] 等失陷指标写法、全角标点与全角字母、
// 首尾引号、末尾句读、协议相对 //、反斜杠、零宽字符、URL 内嵌凭据、
// 默认端口、host 大小写与末尾根点、锚点（fragment）。
package target

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// NormalizeResult URL 归一化结果。
type NormalizeResult struct {
	Raw      string   // 原始输入
	URL      string   // 归一化后的 URL（空输入时为空）
	Changes  []string // 修正说明（人类可读，按发生顺序；无修正时为空）
	Fragment string   // 被移除的锚点（仅记录，不参与扫描）
}

var (
	// schemeWithSepRE 形如 http:// / https:// / ftp:// …（任意协议 + //）。
	schemeWithSepRE = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)
	// schemeSepRE 协议已出现但分隔符不规范：http:\\  http:/  https:///。
	schemeSepRE = regexp.MustCompile(`(?i)^(https?):[\\/]+`)
	// schemeNoSepRE 形如 http:example.com（缺 //）。
	schemeNoSepRE = regexp.MustCompile(`(?i)^(https?):([^/\\].*)$`)
	// knownOtherSchemeRE 明确不是 http(s) 的协议：保持原样交给 Validate 拒绝，
	// 不能把 javascript:/data:/ftp: 误补成 https://…
	knownOtherSchemeRE = regexp.MustCompile(`(?i)^(ftp|file|javascript|data|mailto|tel|ssh|smb|ws|wss):`)
	// defangRE 失陷指标写法：[.] (.) [dot] (dot) [:] [/] [@]（大小写不敏感）。
	defangRE = regexp.MustCompile(`(?i)\[(?:\.|dot|:|\/|@)\]|\((?:\.|dot)\)`)
	// hxxpRE 失陷指标协议：hxxp:// / hxxps://（大小写不敏感）。
	hxxpRE = regexp.MustCompile(`(?i)^hxxp(s?)://`)
)

// trailingPunct 粘贴时常见的中文句读/收尾标点（只在末尾剥离）。
const trailingPunct = "。，、；）】》”’！？"

// Normalize 归一化用户输入 URL。空输入返回空结果。
func Normalize(raw string) NormalizeResult {
	res := NormalizeResult{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		return res
	}
	var changes []string
	add := func(msg string) {
		for _, c := range changes {
			if c == msg {
				return
			}
		}
		changes = append(changes, msg)
	}
	if s != raw {
		add("去除首尾空白")
	}

	// 1) 零宽字符（聊天/网页复制常见）
	if z := strings.Map(func(r rune) rune {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\ufeff':
			return -1
		}
		return r
	}, s); z != s {
		s = z
		add("去除零宽字符")
	}

	// 2) 首尾引号/书名号/尖括号（<https://…>、“https://…”）
	if q := strings.Trim(s, "\"'`<>“”‘’《》"); q != s {
		s = q
		add("去除首尾引号/书名号")
	}

	// 3) 末尾中文句读（example.com。 / …）】；放在全角折叠之前，避免 ） → )
	//    之后反而认不出是句读。
	if t := strings.TrimRight(s, trailingPunct); t != s {
		s = t
		add("去除末尾标点")
	}

	// 4) 全角字符 → 半角（https：//、example．com、ｇｏｖ．ｃｎ）
	if f := foldFullWidth(s); f != s {
		s = f
		add("全角字符转半角")
	}

	// 5) 从粘贴文本里提取唯一 URL（“见 https://a.com 谢谢”）
	if !schemeWithSepRE.MatchString(s) {
		if u := extractSingleURL(s); u != "" {
			s = u
			add("从粘贴文本中提取 URL")
		}
	}

	// 6) 失陷指标还原：[.] → .、[:] → :，然后再还原 hxxp://
	if d := defangRE.ReplaceAllStringFunc(s, defangToken); d != s {
		s = d
		add("还原失陷指标写法（[.] 等）")
	}
	if m := hxxpRE.FindStringSubmatch(s); m != nil {
		scheme := "http://"
		if m[1] != "" {
			scheme = "https://"
		}
		s = scheme + s[len(m[0]):]
		add("还原 hxxp 为 http(s)")
	}

	// 7) 协议相对地址：//example.com → https://example.com
	if strings.HasPrefix(s, "//") {
		s = "https:" + s
		add("补全协议 https")
	}

	// 8) 协议分隔符规范化：http:\\ / http:/ / https:/// → http(s)://
	if loc := schemeSepRE.FindStringSubmatchIndex(s); loc != nil {
		scheme := s[loc[2]:loc[3]]
		rest := strings.TrimLeft(s[loc[1]:], "\\/")
		if fixed := scheme + "://" + rest; fixed != s {
			s = fixed
			add("规范协议分隔符 //")
		}
	}
	// 9) http:example.com → http://example.com
	if m := schemeNoSepRE.FindStringSubmatch(s); m != nil {
		s = m[1] + "://" + m[2]
		add("补全协议分隔符 //")
	}

	// 10) 缺协议：只对“不像已知协议”的输入补 https，避免把 javascript:/ftp: 带歪
	if !schemeWithSepRE.MatchString(s) && !knownOtherSchemeRE.MatchString(s) {
		s = "https://" + s
		add("补全协议 https")
	}

	// 11) 锚点不发送给目标：记录后移除
	if i := strings.Index(s, "#"); i >= 0 {
		if frag := s[i+1:]; frag != "" {
			res.Fragment = frag
			s = s[:i]
			add("移除锚点（# 后内容不发送）")
		}
	}

	u, err := url.Parse(s)
	if err != nil {
		// 解析不了就把当前形态交给 Validate 给出明确错误；不在这里猜。
		res.URL = s
		res.Changes = changes
		return res
	}
	u.Scheme = strings.ToLower(u.Scheme)

	// 12) URL 内嵌凭据：不静默发送（凭据应走认证配置，且不能进日志/证据）
	if u.User != nil {
		u.User = nil
		add("移除 URL 内嵌凭据（请用扫描认证配置）")
	}

	// 13) host 统一小写、去末尾根点、默认端口省略（同一目标的等价写法）
	if u.Host != "" {
		host := strings.ToLower(u.Hostname())
		changedHost := host != u.Hostname()
		if strings.HasSuffix(host, ".") {
			host = strings.TrimSuffix(host, ".")
			changedHost = true
			add("去除主机名末尾根点")
		}
		if changedHost {
			add("主机名统一小写")
		}
		port := u.Port()
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			port = ""
			add("省略默认端口")
		}
		switch {
		case host == "":
			// 交给 Validate 报“缺少主机名”
		case port != "":
			u.Host = net.JoinHostPort(host, port)
		case strings.Contains(host, ":"):
			u.Host = "[" + host + "]" // IPv6 字面量：保留方括号
		default:
			u.Host = host
		}
	}

	res.URL = u.String()
	res.Changes = changes
	return res
}

// foldFullWidth 全角 ASCII（U+FF01–U+FF5E）与全角空格（U+3000）→ 半角。
// 只做确定的码位映射，不做 Unicode 归一化/IDNA。
func foldFullWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for _, r := range s {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			b.WriteRune(r - 0xFEE0)
			changed = true
		case r == 0x3000:
			b.WriteRune(' ')
			changed = true
		case r == 0x3002 || r == 0xFF61:
			// 中文句号/半角句号在 URL 语境里几乎都是误用的点
			// （example。com / https://…。路径）；句末的已被前置步骤剥掉。
			b.WriteRune('.')
			changed = true
		default:
			b.WriteRune(r)
		}
	}
	if !changed {
		return s
	}
	return b.String()
}

// defangToken 把 [.] (.) [dot] (dot) [:] [/] [@] 还原成对应字符。
func defangToken(m string) string {
	lower := strings.ToLower(m)
	switch {
	case strings.Contains(lower, ":"):
		return ":"
	case strings.Contains(lower, "/"):
		return "/"
	case strings.Contains(lower, "@"):
		return "@"
	default:
		return "."
	}
}

// extractSingleURL 从“一段话里只有一个 URL”的粘贴内容中取出该 URL。
// 多个 URL 或有歧义时返回空（不做猜测）。
func extractSingleURL(s string) string {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return ""
	}
	var found []string
	for _, f := range fields {
		l := strings.ToLower(f)
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			found = append(found, strings.Trim(f, "，。、；）】》”’\"'<>"))
		}
	}
	if len(found) == 1 {
		return found[0]
	}
	return ""
}

// String 便于日志输出（不带 Raw，避免把用户原始输入重复打进日志）。
func (r NormalizeResult) String() string {
	if len(r.Changes) == 0 {
		return r.URL
	}
	return fmt.Sprintf("%s（修正：%s）", r.URL, strings.Join(r.Changes, "、"))
}
