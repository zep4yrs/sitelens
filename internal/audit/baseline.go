// AU-02 审计基线/忽略（baseline）。
//
// 基线 = 一组「已确认/已接受」发现指纹的集合（JSON 文件）。--baseline 时
// 只输出不在基线内的新发现，并在报告里写 baseline_ignored 计数；
// --update-baseline 时把本轮全部发现指纹写入基线文件（供下次比对）。
//
// 指纹与 SARIF partialFingerprints 完全同源：sha256(ruleId | uri | line |
// match)（见 sarifFingerprint/normalizeSARIFURI）。这样基线与 SARIF 去重
// 口径一致，也保证同一发现在 JSON/SARIF/基线之间身份稳定。
//
// 已知局限（5.3 议题）：指纹包含行号，代码插入/删除导致行号漂移时旧告警
// 会被当成「新增」；跨提交的行号无关归并在 5.3 处理（与 AU-01 风险节一致）。
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	baselineVersion = 1
	baselineTool    = "SiteLens-audit"
)

// Baseline 基线文件结构（fingerprints 升序去重，保证文件可 diff）。
type Baseline struct {
	Version      int      `json:"version"`
	Tool         string   `json:"tool,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	Fingerprints []string `json:"fingerprints"`
}

// Fingerprint 发现指纹：与 SARIF partialFingerprints 同源
// （ruleId | 归一化 uri | 行号 | match 的 sha256）。
func Fingerprint(f Finding) string {
	line := f.Line
	if line < 1 {
		line = 1 // 与 SARIF 的 startLine 归一一致
	}
	return sarifFingerprint(f, normalizeSARIFURI(f.File), line)
}

// NewBaseline 由报告构建基线（全部发现，升序去重）。
func NewBaseline(rep *Report) *Baseline {
	set := map[string]bool{}
	if rep != nil {
		for _, f := range rep.Findings {
			set[Fingerprint(f)] = true
		}
	}
	fps := make([]string, 0, len(set))
	for fp := range set {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	return &Baseline{
		Version:      baselineVersion,
		Tool:         baselineTool,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Fingerprints: fps,
	}
}

// Save 原子写出基线文件（tmp+rename，避免半截文件）。
func (b *Baseline) Save(path string) error {
	if b == nil {
		b = &Baseline{Version: baselineVersion, Tool: baselineTool, Fingerprints: []string{}}
	}
	if b.Fingerprints == nil {
		b.Fingerprints = []string{} // 空基线序列化为 [] 而非 null
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadBaseline 读取基线文件（缺失/损坏/非对象均报错——显式指定基线的
// 场景静默忽略会掩盖「基线没生效」）。空白文件按空基线处理。
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Baseline{Version: baselineVersion, Tool: baselineTool, Fingerprints: []string{}}, nil
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("基线文件不是合法 JSON：%w", err)
	}
	if b.Fingerprints == nil {
		b.Fingerprints = []string{}
	}
	return &b, nil
}

// ApplyBaseline 过滤报告中已在基线的发现，返回被忽略条数。
// 同时按过滤后的结果重算 BySeverity（计数必须与 findings 自洽）。
func ApplyBaseline(rep *Report, b *Baseline) int {
	if rep == nil {
		return 0
	}
	set := map[string]bool{}
	if b != nil {
		for _, fp := range b.Fingerprints {
			set[fp] = true
		}
	}
	kept := make([]Finding, 0, len(rep.Findings))
	by := map[string]int{"high": 0, "medium": 0, "low": 0}
	ignored := 0
	for _, f := range rep.Findings {
		if set[Fingerprint(f)] {
			ignored++
			continue
		}
		kept = append(kept, f)
		by[f.Severity]++
	}
	rep.Findings = kept
	rep.BySeverity = by
	return ignored
}
