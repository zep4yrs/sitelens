package server

import (
	"net/url"
	"strings"
)

// batchItem 批量扫描的单条目标（URL + 可选档位预设）。
type batchItem struct {
	URL   string `json:"url"`
	Level string `json:"level,omitempty"`
}

// batchRequest /api/batch 请求体：entries 优先，urls 兼容旧客户端。
type batchRequest struct {
	URLs    []string    `json:"urls"`
	Entries []batchItem `json:"entries"`
}

// batchLevels 允许的档位（与 scanOptions/levelPresets 对齐；空 = 默认）。
var batchLevels = map[string]bool{
	"": true, "quick": true, "standard": true, "deep": true, "full": true,
	"stealth": true, "assets": true, "apocalypse": true,
}

// batchLevelAlias 中文档位别名（UI 输入友好）。
var batchLevelAlias = map[string]string{
	"快速": "quick", "标准": "standard", "深度": "deep", "完整": "full",
	"隐身": "stealth", "资产": "assets",
}

// normalizeBatchItem 解析一行目标：`url` 或 `url 档位`（档位支持中英文）。
// URL 内可能带空格（少见），只把最后一个 token 当档位；无法识别则整行当 URL。
func normalizeBatchItem(raw string) batchItem {
	s := strings.TrimSpace(raw)
	if s == "" {
		return batchItem{}
	}
	parts := strings.Fields(s)
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		lv := strings.ToLower(last)
		if alias, ok := batchLevelAlias[last]; ok {
			lv = alias
		}
		if batchLevels[lv] && lv != "" {
			return batchItem{URL: strings.Join(parts[:len(parts)-1], " "), Level: lv}
		}
	}
	return batchItem{URL: s}
}

// parseBatchItems 合并 entries + urls，归一化并截断到上限；空 URL 丢弃。
func parseBatchItems(req batchRequest, max int) []batchItem {
	var out []batchItem
	appendItem := func(it batchItem) {
		if len(out) >= max {
			return
		}
		it.URL = strings.TrimSpace(it.URL)
		if it.URL == "" {
			return
		}
		if !batchLevels[strings.ToLower(it.Level)] {
			it.Level = ""
		} else {
			it.Level = strings.ToLower(it.Level)
		}
		out = append(out, it)
	}
	for _, it := range req.Entries {
		appendItem(it)
	}
	for _, raw := range req.URLs {
		appendItem(normalizeBatchItem(raw))
	}
	return out
}

// batchHost 取 URL 主机（用于同 host 串行）；解析失败时退回原串。
func batchHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	return strings.ToLower(u.Hostname())
}
