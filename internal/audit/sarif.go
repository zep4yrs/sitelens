// SARIF 2.1.0 导出（AU-01）。
//
// 目标：把既有审计发现（Report.Findings）映射为 SARIF，供 GitHub code
// scanning 与其他 SARIF 消费方读取。**只做导出**：不改规则、不改判定、不改
// 既有 JSON 报告结构（additive：仅新增本文件与 CLI 的 --sarif 出口）。
//
// 映射口径：
//   - ruleId 取 Finding.Rule。rules[] 按 ruleId 升序去重；name/shortDescription
//     优先取规则表元数据（AST-/TAINT- 等动态规则回退到发现自带 Title），
//     advice 落入 help.text；无 helpUri 元数据则省略该字段。
//   - level：high→error、medium→warning、low→note（未知严重度回退 warning，
//     不静默降级成 note）。
//   - location：artifactLocation.uri 为相对斜杠路径并按 URI path 规则做
//     百分号编码；region.startLine 为行号（<1 归一为 1，SARIF 要求 >=1）。
//   - partialFingerprints：sha256(ruleId | uri | line | match)。同一输入两次
//     导出逐字节一致，供告警去重与跨次比对；跨提交行号漂移的基线归并是
//     5.3 的议题（见 release 文档 AU-01 风险节），本轮不做。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	// sarifVersion SARIF 规范版本（2.1.0 是 GitHub code scanning 接受版本）。
	sarifVersion = "2.1.0"
	// sarifSchemaURL 供校验器/编辑器按图索骥；不参与语义。
	sarifSchemaURL = "https://json.schemastore.org/sarif-2.1.0.json"
	// sarifToolName 工具名（出现于 runs[0].tool.driver.name）。
	sarifToolName = "SiteLens"
	// sarifFingerprintKey 指纹键：GitHub 用它做告警身份匹配。
	sarifFingerprintKey = "primaryLocationLineHash"
)

// ToSARIF 把审计报告导出为 SARIF 2.1.0 JSON（缩进 2 空格，便于人工 diff）。
//
// rep 为 nil 按空报告处理；toolVersion 为空时省略 driver.version。
// 返回的字节是确定性输出：同一 Report（同一顺序的 Findings）两次导出完全相同。
func ToSARIF(rep *Report, toolVersion string) ([]byte, error) {
	if rep == nil {
		rep = &Report{}
	}

	// 规则元数据：按 ruleId 去重（保留首个发现的 Title/Advice），排序保证
	// rules[] 与 ruleIndex 稳定（map 迭代顺序不可依赖）。
	ruleTitle := map[string]string{}
	ruleAdvice := map[string]string{}
	ruleIDs := make([]string, 0)
	for _, f := range rep.Findings {
		if _, ok := ruleTitle[f.Rule]; ok {
			continue
		}
		ruleIDs = append(ruleIDs, f.Rule)
		ruleTitle[f.Rule] = f.Title
		ruleAdvice[f.Rule] = f.Advice
	}
	sort.Strings(ruleIDs)

	ruleIndex := make(map[string]int, len(ruleIDs))
	rules := make([]sarifRule, 0, len(ruleIDs))
	for i, id := range ruleIDs {
		ruleIndex[id] = i
		r := sarifRule{ID: id, Name: id}
		title := ruleTitle[id]
		if title == "" {
			title = id
		}
		r.ShortDescription = &sarifText{Text: title}
		if adv := ruleAdvice[id]; adv != "" {
			r.Help = &sarifText{Text: adv}
		}
		rules = append(rules, r)
	}

	results := make([]sarifResult, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		uri := normalizeSARIFURI(f.File)
		line := f.Line
		if line < 1 {
			line = 1
		}
		res := sarifResult{
			RuleID:              f.Rule,
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{Text: findingMessage(f)},
			PartialFingerprints: map[string]string{sarifFingerprintKey: sarifFingerprint(f, uri, line)},
		}
		if idx, ok := ruleIndex[f.Rule]; ok {
			i := idx
			res.RuleIndex = &i
		}
		if uri != "" {
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
				Region:           sarifRegion{StartLine: line},
			}}}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchemaURL,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    sarifToolName,
				Version: toolVersion,
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

// sarifLevel 严重度 → SARIF level（high→error / medium→warning / low→note）。
func sarifLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		// 未知严重度按 warning 处理：宁可让消费方看见，也不静默压成 note
		return "warning"
	}
}

// findingMessage 生成 results[].message.text：标题 + 命中片段（截断已在
// 规则命中时做过，最长 160 字符）。
func findingMessage(f Finding) string {
	title := strings.TrimSpace(f.Title)
	snippet := strings.TrimSpace(f.Snippet)
	switch {
	case title != "" && snippet != "":
		return title + "：" + snippet
	case title != "":
		return title
	case snippet != "":
		return snippet
	default:
		return f.Rule // 兜底：message 不能为空串
	}
}

// normalizeSARIFURI 把发现里的文件路径归一为 SARIF artifactLocation.uri：
//   - 反斜杠统一为 "/"（跨平台确定性，不依赖 filepath.ToSlash 的宿主行为）；
//   - 去除 "./" 段并折叠多余分隔符；
//   - 绝对路径（含 Windows 盘符/UNC）退化为基名——SARIF 只应携带相对路径，
//     避免把审计主机绝对路径写进报告；
//   - 越界 ".." 路径退化为基名（正常审计不会产生，纯防御）；
//   - 最后按 URI path 规则百分号编码（空格/中文/特殊字符）。
//
// 无法归一为空路径（".", "..", ""）时返回 ""，调用方不产出 location。
func normalizeSARIFURI(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, "/")
	// 绝对路径：POSIX 根、Windows 盘符（C:/x）或 UNC（//host/share）
	if path.IsAbs(p) || (len(p) >= 2 && p[1] == ':') {
		p = path.Base(p)
	}
	p = path.Clean(p)
	if p == "." || p == "" {
		return ""
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		p = path.Base(p)
		if p == "." || p == ".." {
			return ""
		}
	}
	// 百分号编码：保留 "/" 分隔，转义空格/中文/#/? 等 URI 保留字符。
	// （URL.EscapedPath 对已含 % 的字面量会再转义，不会双重解码）
	return (&url.URL{Path: p}).EscapedPath()
}

// sarifFingerprint 稳定指纹：sha256(ruleId | uri | line | match)。
// 同一发现（同规则/同文件/同行/同命中片段）在任何一次导出都得同一值；
// 任一项变化（如行号漂移）则视为不同告警。
func sarifFingerprint(f Finding, uri string, line int) string {
	h := sha256.New()
	for _, part := range []string{f.Rule, uri, strconv.Itoa(line), f.Match} {
		h.Write([]byte(part))
		h.Write([]byte{0}) // 分隔符：防 ["ab","c"] 与 ["a","bc"] 碰撞
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- SARIF 2.1.0 结构（只声明导出用到的字段） ----

type sarifLog struct {
	Schema  string     `json:"$schema,omitempty"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name,omitempty"`
	ShortDescription *sarifText `json:"shortDescription,omitempty"`
	Help             *sarifText `json:"help,omitempty"`
	HelpURI          string     `json:"helpUri,omitempty"` // 现无规则元数据 URI：省略
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
