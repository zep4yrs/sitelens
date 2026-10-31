package apispec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// harDoc HAR 1.2 的最小结构（只取本包需要的字段）。
type harDoc struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	Request harRequest `json:"request"`
}

type harRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Query    []harName   `json:"query"`
	PostData harPostData `json:"postData"`
}

type harName struct {
	Name string `json:"name"`
}

type harPostData struct {
	MimeType string    `json:"mimeType"`
	Text     string    `json:"text"`
	Params   []harName `json:"params"`
}

// ParseHAR 解析浏览器/代理导出的 HAR（HTTP Archive）请求记录，抽取端点：
// method + URL 路径 + query 参数名 + 请求体字段名（params / JSON / 表单编码）。
// 结果按 (method, path) 去重并合并参数名；重复条目不影响计数。
//
// 与 OpenAPI 一样离线解析、不执行；输入上限 8MB。
func ParseHAR(data []byte) (*Spec, error) {
	if err := checkSize(data); err != nil {
		return nil, err
	}
	body := trimBOM(data)
	if len(body) == 0 {
		return nil, fmt.Errorf("apispec: 空输入")
	}
	if !looksJSON(body) {
		return nil, ErrUnsupportedYAML
	}
	var doc harDoc
	if err := jsonDecodeStrict(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.Log.Entries) == 0 {
		return nil, fmt.Errorf("apispec: HAR 没有 log.entries")
	}
	spec := &Spec{Source: "har", Version: doc.Log.Version}
	for _, e := range doc.Log.Entries {
		req := e.Request
		u, err := url.Parse(strings.TrimSpace(req.URL))
		if err != nil || u.Host == "" {
			continue // 相对地址/坏条目跳过，不让单条坏数据毁掉整份记录
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		params := []string{}
		// query 参数名：以实际 URL 为准，再补 HAR 显式 query 数组
		// （map 遍历无序，按字典序输出保证重复解析结果一致）。
		for _, name := range sortedKeys(u.Query()) {
			params = append(params, name)
		}
		for _, q := range req.Query {
			params = append(params, q.Name)
		}
		params = append(params, harBodyFields(req.PostData)...)
		spec.AddEndpoint(req.Method, path, params...)
	}
	spec.Dedup()
	return spec, nil
}

// harBodyFields 抽取请求体字段名：优先 postData.params（HAR 已结构化字段），
// 再看 postData.text（JSON 对象顶层键 / x-www-form-urlencoded 键）。
func harBodyFields(pd harPostData) []string {
	var out []string
	for _, p := range pd.Params {
		out = append(out, p.Name)
	}
	text := strings.TrimSpace(pd.Text)
	if text == "" {
		return out
	}
	mime := strings.ToLower(pd.MimeType)
	if strings.Contains(mime, "json") || (mime == "" && looksJSON([]byte(text))) {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &obj) == nil {
			out = append(out, sortedKeys(obj)...)
			return out
		}
	}
	if strings.Contains(mime, "x-www-form-urlencoded") || strings.Contains(text, "=") {
		if vals, err := url.ParseQuery(text); err == nil {
			for _, name := range sortedKeys(vals) {
				out = append(out, name)
			}
		}
	}
	return out
}
