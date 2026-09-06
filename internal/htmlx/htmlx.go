// Package htmlx 轻量 HTML 提取：标题 / 链接 / 脚本 / meta / 表单。
//
// 不引入完整 DOM 解析器：扫描器只需要标签级信号，
// 正则+索引扫描足够且比 encoding/html 慢解析快一个量级。
package htmlx

import (
	"strings"
)

// Input 表单字段。
type Input struct {
	Name string
	Type string
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
	HasPassword bool // 是否存在 password 输入框（登录页特征）
}

// Parse 解析 HTML 原文。
func Parse(body string) *Doc {
	doc := &Doc{Metas: map[string]string{}, Links: []string{}, ScriptSrcs: []string{}}
	low := strings.ToLower(body)
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
		if src := attrValue(tagText, "src"); src != "" {
			doc.ScriptSrcs = append(doc.ScriptSrcs, src)
		}
		closeIdx := strings.Index(low[start:], "</script>")
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
		if nf := strings.Index(strings.ToLower(region), "<form"); nf >= 0 {
			region = region[:nf]
			regionEnd = nf
		}
		if ef := strings.Index(strings.ToLower(region), "</form>"); ef >= 0 && ef < regionEnd {
			region = region[:ef]
		}
		ipos := 0
		lowRegion := strings.ToLower(region)
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
				Name: attrValue(iTag, "name"),
				Type: strings.ToLower(attrValue(iTag, "type")),
			}
			if in.Type == "password" {
				form.HasPassword = true
				doc.HasPassword = true
			}
			if in.Name != "" {
				form.Inputs = append(form.Inputs, in)
			}
			ipos = istart + iEnd + 1
		}
		doc.Forms = append(doc.Forms, form)
		pos = start + tagEnd + 1 + regionEnd
	}
	return doc
}

// attrValue 从单个标签原文取属性值（单/双引号或无引号，大小写不敏感）。
func attrValue(tagText, attr string) string {
	low := strings.ToLower(tagText)
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
