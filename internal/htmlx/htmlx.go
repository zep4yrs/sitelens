// Package htmlx 轻量 HTML 提取：标题 / 链接 / 脚本 / meta / 表单。
//
// 不引入完整 DOM 解析器：扫描器只需要标签级信号，
// 正则+索引扫描足够且比 encoding/html 慢解析快一个量级。
package htmlx

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Input 表单字段。
type Input struct {
	Name        string
	Type        string
	ID          string
	Placeholder string
	Value       string
}

// Form 页面表单。
type Form struct {
	Action      string
	Method      string
	Inputs      []Input
	HasPassword bool // 表单内存在 password 输入框（登录表单特征）
}

// Doc 一次 HTML 解析提取的全部信号。
type Doc struct {
	Title       string
	Links       []string          // <a href> 原始值（保序去重）
	ScriptSrcs  []string          // <script src>
	Metas       map[string]string // meta name/property(小写) → content
	Forms       []Form
	HasPassword bool     // 是否存在 password 输入框（登录页特征）
	NextRoutes  []string // SPA 数据岛（__NEXT_DATA__/__NUXT__）中的路由路径
	CaptchaImgs []string // 疑似验证码图片地址（img src 含 captcha/code/verify 线索）
}

// Parse 解析 HTML 原文。
func Parse(body string) *Doc {
	// 关键：用长度保持的 ASCII 小写化，而非 strings.ToLower——
	// ToLower 会改变非 ASCII 字节的字节长度（İ 等特殊字符、非法 UTF-8
	// 膨胀为 RuneError），使 low 上的索引与 body 错位导致越界切片
	//（模糊测试 FuzzParse 发现的真实崩溃）。
	doc := &Doc{Metas: map[string]string{}, Links: []string{}, ScriptSrcs: []string{}}
	low := asciiLower(body)
	seenLinks := map[string]bool{}

	// <title>
	if s := strings.Index(low, "<title"); s >= 0 {
		if gt := strings.Index(low[s:], ">"); gt >= 0 {
			start := s + gt + 1
			if e := strings.Index(low[start:], "</title>"); e >= 0 {
				doc.Title = strings.TrimSpace(body[start : start+e])
			}
		}
	}

	// <a href>
	pos := 0
	for {
		i := strings.Index(low[pos:], "<a ")
		if i < 0 {
			break
		}
		start := pos + i
		tagEnd := strings.Index(low[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagText := body[start : start+tagEnd+1]
		if href := attrValue(tagText, "href"); href != "" && !seenLinks[href] {
			seenLinks[href] = true
			doc.Links = append(doc.Links, href)
		}
		pos = start + tagEnd + 1
	}

	// <script src> 与内联脚本
	pos = 0
	for {
		i := strings.Index(low[pos:], "<script")
		if i < 0 {
			break
		}
		start := pos + i
		tagEnd := strings.Index(low[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagText := body[start : start+tagEnd+1]
		closeIdx := strings.Index(low[start:], "</script>")
		src := attrValue(tagText, "src")
		if src == "" && closeIdx >= 0 {
			// SPA 数据岛：__NEXT_DATA__（JSON 岛）与 __NUXT__（内联 JS，
			// 退化为引号内路径提取）两类都贡献路由
			inner := body[start+tagEnd+1 : start+closeIdx]
			if isSPAJet(tagText) || strings.Contains(asciiLower(inner), "window.__nuxt__") {
				doc.NextRoutes = append(doc.NextRoutes, spaRoutes(inner)...)
			}
		}
		if src != "" {
			doc.ScriptSrcs = append(doc.ScriptSrcs, src)
		}
		if closeIdx < 0 {
			pos = start + tagEnd + 1
			continue
		}
		pos = start + closeIdx + len("</script>")
	}

	// <meta>
	pos = 0
	for {
		i := strings.Index(low[pos:], "<meta")
		if i < 0 {
			break
		}
		start := pos + i
		tagEnd := strings.Index(low[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagText := body[start : start+tagEnd+1]
		name := attrValue(tagText, "name")
		if name == "" {
			name = attrValue(tagText, "property")
		}
		content := attrValue(tagText, "content")
		if name != "" && content != "" {
			doc.Metas[strings.ToLower(name)] = content
		}
		pos = start + tagEnd + 1
	}

	// <img>：仅收集疑似验证码图片（src/边邻属性含验证码线索词）
	pos = 0
	for {
		i := strings.Index(low[pos:], "<img")
		if i < 0 {
			break
		}
		start := pos + i
		tagEnd := strings.Index(low[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagText := body[start : start+tagEnd+1]
		if s := attrValue(tagText, "src"); s != "" && isCaptchaImg(tagText) {
			doc.CaptchaImgs = append(doc.CaptchaImgs, s)
		}
		pos = start + tagEnd + 1
	}

	// <form>
	pos = 0
	for {
		i := strings.Index(low[pos:], "<form")
		if i < 0 {
			break
		}
		start := pos + i
		tagEnd := strings.Index(low[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagText := body[start : start+tagEnd+1]
		form := Form{
			Action: attrValue(tagText, "action"),
			Method: strings.ToUpper(attrValue(tagText, "method")),
		}
		if form.Method == "" {
			form.Method = "GET"
		}
		// 表单内的 <input>：到 </form> 或下一个 <form 为止
		region := body[start+tagEnd+1:]
		regionEnd := len(region)
		lowRegionFull := asciiLower(region)
		if nf := strings.Index(lowRegionFull, "<form"); nf >= 0 {
			region = region[:nf]
			regionEnd = nf
		}
		if ef := strings.Index(lowRegionFull, "</form>"); ef >= 0 && ef < regionEnd {
			region = region[:ef]
		}
		ipos := 0
		lowRegion := asciiLower(region)
		for {
			ii := strings.Index(lowRegion[ipos:], "<input")
			if ii < 0 {
				break
			}
			istart := ipos + ii
			iEnd := strings.Index(lowRegion[istart:], ">")
			if iEnd < 0 {
				break
			}
			iTag := region[istart : istart+iEnd+1]
			in := Input{
				Name:        attrValue(iTag, "name"),
				Type:        strings.ToLower(attrValue(iTag, "type")),
				ID:          attrValue(iTag, "id"),
				Placeholder: attrValue(iTag, "placeholder"),
				Value:       attrValue(iTag, "value"),
			}
			if in.Type == "" {
				in.Type = "text"
			}
			if in.Type == "password" {
				form.HasPassword = true
				doc.HasPassword = true
			}
			// 无 name 但有 id/placeholder 的输入也收集（登录爆破按 id/placeholder 推断字段）
			if in.Name != "" || in.ID != "" || in.Placeholder != "" {
				form.Inputs = append(form.Inputs, in)
			}
			ipos = istart + iEnd + 1
		}
		doc.Forms = append(doc.Forms, form)
		pos = start + tagEnd + 1 + regionEnd
	}
	return doc
}

// asciiLower 仅将 A-Z 转小写，字节长度不变——索引与原文严格对齐。
func asciiLower(s string) string {
	has := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			has = true
			break
		}
	}
	if !has {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// isSPAJet 该 script 标签是否为 SPA 数据岛（__NEXT_DATA__ 等 JSON 岛）。
func isSPAJet(tagText string) bool {
	low := asciiLower(tagText)
	return strings.Contains(low, `id="__next_data__"`) ||
		strings.Contains(low, `type="application/json"`) ||
		strings.Contains(low, `type='application/json'`)
}

// 路径含斜杠，字符类必须包含 /；- 放在类尾避免被读作区间
var nuxtPathRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_./-]{1,80})["']`)

// spaRoutes 从 SPA 数据岛内容提取路由样路径（/ 开头、无空格、限长）。
func spaRoutes(inner string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] && len(out) < 200 {
			seen[s] = true
			out = append(out, s)
		}
	}
	// __NEXT_DATA__：标准 JSON，遍历找 route/page/href/url 键
	var v any
	if err := json.Unmarshal([]byte(inner), &v); err == nil {
		var walk func(n any)
		walk = func(n any) {
			switch t := n.(type) {
			case map[string]any:
				for k, vv := range t {
					switch k {
					case "route", "page", "href", "url":
						if s, ok := vv.(string); ok && strings.HasPrefix(s, "/") &&
							!strings.Contains(s, " ") {
							add(s)
						}
					}
					walk(vv)
				}
			case []any:
				for _, vv := range t {
					walk(vv)
				}
			}
		}
		walk(v)
		return out
	}
	// __NUXT__：JS 赋值非标准 JSON，退化为提取引号包裹的路径样字符串
	for _, m := range nuxtPathRe.FindAllStringSubmatch(inner, -1) {
		add(m[1])
	}
	return out
}

// isCaptchaImg 判断 img 标签是否疑似验证码图（src/id/class/边邻属性含线索词）。
func isCaptchaImg(tagText string) bool {
	low := strings.ToLower(tagText)
	for _, kw := range []string{"captcha", "verif", "vcode", "validate", "checkcode", "verify"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// attrValue 从单个标签原文取属性值（单/双引号或无引号，大小写不敏感）。
func attrValue(tagText, attr string) string {
	// 长度保持小写化（asciiLower）：索引须与 tagText 对齐，
	// strings.ToLower 的非 ASCII 字节膨胀曾导致越界（fuzz 发现）
	low := asciiLower(tagText)
	key := attr + "="
	i := strings.Index(low, key)
	if i < 0 {
		return ""
	}
	rest := tagText[i+len(key):]
	if rest == "" {
		return ""
	}
	q := rest[0]
	if q == '"' || q == '\'' {
		end := strings.IndexByte(rest[1:], q)
		if end < 0 {
			return rest[1:]
		}
		return rest[1 : 1+end]
	}
	end := strings.IndexAny(rest, " \t\n\r>")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
