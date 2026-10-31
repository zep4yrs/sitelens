package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/store"
)

// SARIF 2.1.0 最小结构（扫描结果导出；与审计 SARIF 独立，字段语义按发现来源映射）。
type sarifLog struct {
	Schema  string     `json:"$schema"`
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
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name,omitempty"`
	ShortDescription sarifText  `json:"shortDescription"`
	Help             *sarifText `json:"help,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// severityToSARIFLevel 统一严重度 → SARIF level。
func severityToSARIFLevel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high", "严重", "高危":
		return "error"
	case "medium", "中危":
		return "warning"
	case "low", "info", "低危", "信息":
		return "note"
	default:
		return "warning"
	}
}

// scanSARIF 把一次扫描结果（历史记录）转成 SARIF 2.1.0。
// 覆盖 vulnerabilities（情报/CVE 关联）与 verified（验证型发现）两类；
// 位置用目标 URL（扫描器没有源码行号），指纹 = sha256(ruleId|uri|title)。
func scanSARIF(rec *store.ScanRecord) ([]byte, error) {
	if rec == nil || rec.Result == nil {
		return nil, fmt.Errorf("记录无详细结果数据")
	}
	res := rec.Result
	uri := res.URL
	if uri == "" {
		uri = res.Host
	}
	ruleIndex := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	addRule := func(id, name, desc, help string) int {
		if idx, ok := ruleIndex[id]; ok {
			return idx
		}
		idx := len(rules)
		ruleIndex[id] = idx
		r := sarifRule{ID: id, Name: name, ShortDescription: sarifText{Text: desc}}
		if help != "" {
			r.Help = &sarifText{Text: help}
		}
		rules = append(rules, r)
		return idx
	}
	addResult := func(ruleID, title, desc, sev string) {
		idx := addRule(ruleID, "", title, "")
		fp := sha256.Sum256([]byte(ruleID + "|" + uri + "|" + title))
		msg := title
		if desc != "" && desc != title {
			msg = title + "：" + desc
		}
		results = append(results, sarifResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     severityToSARIFLevel(sev),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: uri},
				Region:           &sarifRegion{StartLine: 1},
			}}},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": hex.EncodeToString(fp[:])},
		})
	}

	for _, v := range res.Vulnerabilities {
		ruleID := "sitelens-intel"
		if v.CVE != "" {
			ruleID = v.CVE
		} else if v.Tech != "" {
			ruleID = "sitelens-tech-" + sanitizeRuleID(v.Tech)
		}
		title := v.Title
		if title == "" {
			title = v.Name
		}
		addResult(ruleID, title, v.Desc, v.Severity)
	}
	for _, m := range res.Verified {
		title := mapString(m, "title", "name", "type", "check")
		if title == "" {
			continue
		}
		sev := mapString(m, "severity", "level", "severity_zh")
		src := mapString(m, "src")
		ruleID := "sitelens-verified"
		if src != "" {
			ruleID = "sitelens-verified-" + sanitizeRuleID(src)
		}
		addResult(ruleID, title, mapString(m, "evidence", "detail", "desc"), sev)
	}

	out := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "SiteLens", Version: "5.2.0",
				InformationURI: "https://cnb.cool/feng-qiao/sitelens",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	if out.Runs[0].Results == nil {
		out.Runs[0].Results = []sarifResult{}
	}
	if out.Runs[0].Tool.Driver.Rules == nil {
		out.Runs[0].Tool.Driver.Rules = []sarifRule{}
	}
	return json.MarshalIndent(out, "", "  ")
}

func mapString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func sanitizeRuleID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
