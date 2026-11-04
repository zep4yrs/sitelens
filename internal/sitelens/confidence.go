// CP-11 指纹置信度校准（纯函数，无 IO）。
//
// 目标：把「命中数量」升级为「可解释的置信度」——对现有 tech 指纹命中做
// 证据计数、通道强度加权、同页多指纹冲突降权、版本号交叉校验，输出
// confidence(0-1) 与 reasons，供 engine 侧写入 Tech.Confidence（0-100）与
// 前端展示「为什么判定为该技术」。
//
// 设计口径（与既有匹配器解耦）：
//   - 不修改 Matcher/Evidence/匹配逻辑；输入是命中结果（Hit/MatchHit）或
//     已抽取的置信信号，因此可在匹配之后任意接入；
//   - 同一页面出现多个技术命中 = 冲突：强通道（header/cookie/meta/icon）
//     证据降权小，正文关键词/正则等弱证据降权大（DVWA 曾单页判 58 项技术）；
//   - 版本号交叉校验：header/body/meta/src 等不同来源给出的版本不一致时，
//     标记 LowConfidence 并降权（同来源重复出现同版本不算冲突）；
//   - 无任何证据 → confidence=0（不臆造）。
package sitelens

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// 证据通道名（ChannelOfEvidence 的输出，也是 reasons 里展示的粒度）。
const (
	ChannelHeader = "header" // 响应头（强）
	ChannelCookie = "cookie" // Set-Cookie 名（强）
	ChannelMeta   = "meta"   // meta 标签（强）
	ChannelIcon   = "icon"   // favicon icon_hash（强）
	ChannelSrc    = "src"    // 外链脚本地址（中）
	ChannelInline = "inline" // 内联脚本（弱）
	ChannelBody   = "body"   // 正文关键词/正则（弱）
	ChannelOther  = "other"  // 未识别形态（弱）
)

// 置信度权重（集中定义，便于评审/调参；最终 clamp 到 [0,1]）。
const (
	defaultBaseConfidence  = 0.50 // 指纹库未给基础置信度时的中性值
	strongChannelBonus     = 0.07 // 每个强通道
	strongChannelCap       = 0.21
	mediumChannelBonus     = 0.04 // 每个中通道
	mediumChannelCap       = 0.08
	weakChannelBonus       = 0.02 // 每个弱通道
	weakChannelCap         = 0.06
	extraPageBonus         = 0.05 // 每多一个页面
	extraPageCap           = 0.10
	conflictStrongPenalty  = 0.05 // 同页冲突 + 该页有强证据
	conflictWeakPenalty    = 0.18 // 同页冲突 + 该页仅有弱证据
	conflictPenaltyCap     = 0.35
	versionConflictPenalty = 0.25 // 版本不一致
)

// ConfidenceSignal 单条指纹证据信号（一条 Hit/MatchHit 或一条通道证据）。
type ConfidenceSignal struct {
	Name     string // 技术名
	Page     string // 页面 URL（同页冲突判定；空 = 未知页面，不参与冲突）
	Channel  string // 通道（见 Channel* 常量；空则按 Evidence 归类）
	Evidence string // 证据描述（Hit.Evidence 原文）
	Version  string // 该证据携带的版本（可空）
	BaseConf int    // 指纹库基础置信度 0-100（0 = 未知，按中性 0.5）
}

// VersionClaim 某来源的版本声明（版本交叉校验输入）。
type VersionClaim struct {
	Name    string // 技术名
	Source  string // header / cookie / meta / body / src / ...
	Version string
	Page    string // 页面（可空；不参与版本一致性判定）
}

// VersionCheck 版本交叉校验结果。
type VersionCheck struct {
	Consistent    bool     // 无冲突（0/1 个版本）
	Version       string   // 采信版本：唯一版本或出现次数最多者；无法判定为空
	Versions      []string // 去重后的版本（升序）
	Sources       []string // 声明来源（与 Versions 对应去重，便于 reasons）
	LowConfidence bool     // 版本不一致 → 标记 low confidence
}

// ConfidenceResult 单技术的置信度校准结果。
type ConfidenceResult struct {
	Name           string       `json:"name"`
	Confidence     float64      `json:"confidence"` // 0-1
	Reasons        []string     `json:"reasons"`
	EvidenceCount  int          `json:"evidence_count"`
	ChannelCount   int          `json:"channel_count"`
	PageCount      int          `json:"page_count"`
	StrongChannels []string     `json:"strong_channels,omitempty"`
	Conflict       bool         `json:"conflict"`
	ConflictPages  []string     `json:"conflict_pages,omitempty"`
	Version        string       `json:"version,omitempty"`
	VersionCheck   VersionCheck `json:"version_check"`
	LowConfidence  bool         `json:"low_confidence"`
}

// TechConfidenceInput 单技术的校准输入。
type TechConfidenceInput struct {
	Name          string
	Signals       []ConfidenceSignal
	VersionClaims []VersionClaim
	BaseConf      int // 0 = 取信号里的 BaseConf / 中性 0.5
}

// ChannelOfEvidence 按既有 Hit.Evidence 文本形态归类通道。
//
// 形态来自 compiledTech.match（见 fingerprint.go）：
//   - "x-..." 头名=值       → header
//   - "cookie NAME"         → cookie
//   - "meta name=content"   → meta
//   - "icon_hash=N"         → icon
//   - "src URL"             → src
//   - "内联JS ..."           → inline
//   - "关键词 ..." / "正则 ..." → body
func ChannelOfEvidence(evidence string) string {
	e := strings.TrimSpace(evidence)
	switch {
	case e == "":
		return ChannelOther
	case strings.HasPrefix(e, "cookie "):
		return ChannelCookie
	case strings.HasPrefix(e, "meta "):
		return ChannelMeta
	case strings.HasPrefix(e, "icon_hash="):
		return ChannelIcon
	case strings.HasPrefix(e, "src "):
		return ChannelSrc
	case strings.HasPrefix(e, "内联JS"):
		return ChannelInline
	case strings.HasPrefix(e, "关键词"), strings.HasPrefix(e, "正则"):
		return ChannelBody
	case strings.ContainsAny(strings.Fields(e)[0], "="):
		return ChannelHeader
	}
	return ChannelOther
}

// IsStrongChannel 强通道（产品识别的高区分度证据）。
func IsStrongChannel(channel string) bool {
	switch channel {
	case ChannelHeader, ChannelCookie, ChannelMeta, ChannelIcon:
		return true
	}
	return false
}

// SignalsFromHits 把一页的命中（引擎内部 Hit）转成置信信号。
func SignalsFromHits(page string, hits []Hit) []ConfidenceSignal {
	out := make([]ConfidenceSignal, 0, len(hits))
	for _, h := range hits {
		out = append(out, ConfidenceSignal{
			Name: h.Name, Page: page, Channel: ChannelOfEvidence(h.Evidence),
			Evidence: h.Evidence, Version: h.Version, BaseConf: h.Conf,
		})
	}
	return out
}

// SignalsFromMatchHits 把一页的命中（引擎侧 MatchHit）转成置信信号。
func SignalsFromMatchHits(page string, hits []MatchHit) []ConfidenceSignal {
	out := make([]ConfidenceSignal, 0, len(hits))
	for _, h := range hits {
		out = append(out, ConfidenceSignal{
			Name: h.Name, Page: page, Channel: ChannelOfEvidence(h.Evidence),
			Evidence: h.Evidence, Version: h.Version, BaseConf: h.Conf,
		})
	}
	return out
}

// VersionClaimsFromSignals 从信号中提取版本声明（仅取携带版本的信号）。
func VersionClaimsFromSignals(signals []ConfidenceSignal) []VersionClaim {
	out := make([]VersionClaim, 0, len(signals))
	for _, s := range signals {
		if strings.TrimSpace(s.Version) == "" {
			continue
		}
		out = append(out, VersionClaim{Name: s.Name, Source: s.Channel, Version: s.Version, Page: s.Page})
	}
	return out
}

// normalizeVersion 版本比较归一：去空白/去前缀 v/小写（"V1.2.3" ≡ "1.2.3"）。
func normalizeVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "version ")
	v = strings.TrimPrefix(v, "v")
	return v
}

// versionCanonicalKey 版本归一化键（B2-10）：把"精度不同"的同一版本折叠成同一键。
//
// 同一技术从不同来源拿到的版本精度常不一致（header 给 `1.24`、正文给 `1.24.0`；
// 或 `5` vs `5.0`），此前按原始字符串比较 → 判成"版本冲突"→ 无谓降权 + 误标
// low confidence + 报告里给出误导性的"版本不一致"理由。
//
// 规则：去尾部全 0 的数值段（`5.0` → `5`、`1.2.0` → `1.2`），保留预发布段；
// 无法解析成数字段时退回 normalizeVersion 原样比较（不猜测语义）。
func versionCanonicalKey(v string) string {
	v = normalizeVersion(v)
	if v == "" {
		return ""
	}
	base := v
	pre := ""
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		pre = base[i+1:]
		base = base[:i]
	}
	parts := strings.Split(base, ".")
	nums := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return v // 形态异常（"1..2" 等）：不折叠，保持原样
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return v // 非纯数字段：不折叠
			}
		}
		nums = append(nums, p)
	}
	// 去掉尾部 "0" 段（保留至少一段）。有预发布段时不折叠——semver 的
	// 数值段在该场景下是规范形式（`1.0.0-beta` 不能写成 `1-beta`）。
	if pre == "" {
		for len(nums) > 1 && nums[len(nums)-1] == "0" {
			nums = nums[:len(nums)-1]
		}
	}
	// 去前导 0（"01" ≡ "1"）
	for i, n := range nums {
		trimmed := strings.TrimLeft(n, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		nums[i] = trimmed
	}
	key := strings.Join(nums, ".")
	if pre != "" {
		key += "-" + pre
	}
	return key
}

// CrossCheckVersion 版本号交叉校验：不同来源给出不一致版本 → LowConfidence。
// 无版本声明视为「无冲突但未校验」（Consistent=true，Version 为空）。
//
// B2-10：冲突判定按 versionCanonicalKey 折叠后的键进行（`5` ≡ `5.0`），
// 展示仍用首个来源的原始归一化写法。
func CrossCheckVersion(claims []VersionClaim) VersionCheck {
	seen := map[string]bool{}
	counts := map[string]int{}
	sources := map[string][]string{}
	display := map[string]string{} // key → 展示用原始写法（首见）
	var order []string
	for _, c := range claims {
		v := normalizeVersion(c.Version)
		if v == "" {
			continue
		}
		key := versionCanonicalKey(v)
		if key == "" {
			continue
		}
		if !seen[key] {
			seen[key] = true
			order = append(order, key)
			display[key] = v
		}
		counts[key]++
		src := strings.TrimSpace(c.Source)
		if src == "" {
			src = ChannelOther
		}
		if !containsString(sources[key], src) {
			sources[key] = append(sources[key], src)
		}
	}
	vc := VersionCheck{Consistent: true}
	if len(order) == 0 {
		return vc
	}
	order = append([]string(nil), order...)
	sort.Slice(order, func(i, j int) bool { return display[order[i]] < display[order[j]] })
	for _, key := range order {
		vc.Versions = append(vc.Versions, display[key])
	}
	// 采信版本：出现次数最多（并列取展示值字典序最小，保证确定性）。
	best := order[0]
	for _, key := range order {
		if counts[key] > counts[best] ||
			(counts[key] == counts[best] && display[key] < display[best]) {
			best = key
		}
	}
	vc.Version = display[best]
	for _, key := range order {
		vc.Sources = append(vc.Sources, strings.Join(sources[key], "+"))
	}
	if len(order) > 1 {
		vc.Consistent = false
		vc.LowConfidence = true
	}
	return vc
}

// ScoreTech 单技术置信度校准（不做跨技术同页冲突，等价于独自命中）。
func ScoreTech(in TechConfidenceInput) ConfidenceResult {
	return scoreTech(in, nil)
}

// CalibrateTechs 多技术置信度校准：同页面出现多个技术 → 互相冲突降权
// （强通道降权小、弱通道降权大），并做每技术版本交叉校验。返回顺序与输入一致。
func CalibrateTechs(inputs []TechConfidenceInput) []ConfidenceResult {
	// page → 该页命中的技术集合（用于冲突判定）。
	pageTechs := map[string]map[string]bool{}
	for _, in := range inputs {
		for _, s := range in.Signals {
			if s.Page == "" {
				continue
			}
			set := pageTechs[s.Page]
			if set == nil {
				set = map[string]bool{}
				pageTechs[s.Page] = set
			}
			set[in.Name] = true
		}
	}
	out := make([]ConfidenceResult, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, scoreTech(in, pageTechs))
	}
	return out
}

// scoreTech 单技术打分；pageTechs 非空时做同页冲突降权。
func scoreTech(in TechConfidenceInput, pageTechs map[string]map[string]bool) ConfidenceResult {
	// 版本声明缺省从信号自动提取：接线方只需给命中即可获得版本交叉校验。
	claims := in.VersionClaims
	if len(claims) == 0 {
		claims = VersionClaimsFromSignals(in.Signals)
	}
	res := ConfidenceResult{Name: in.Name, VersionCheck: CrossCheckVersion(claims)}
	if len(in.Signals) == 0 {
		res.Reasons = append(res.Reasons, "无证据：未命中任何通道，置信度 0")
		res.LowConfidence = true
		return res
	}

	// 1) 证据计数：通道/页面去重。
	channelSeen := map[string]bool{}
	pageSeen := map[string]bool{}
	strongSeen := map[string]bool{}
	weakSeen := map[string]bool{}
	mediumSeen := map[string]bool{}
	for _, s := range in.Signals {
		ch := s.Channel
		if ch == "" {
			ch = ChannelOfEvidence(s.Evidence)
		}
		switch {
		case IsStrongChannel(ch):
			strongSeen[ch] = true
		case ch == ChannelSrc:
			mediumSeen[ch] = true
		default:
			weakSeen[ch] = true
		}
		channelSeen[ch] = true
		if s.Page != "" {
			pageSeen[s.Page] = true
		}
	}
	res.EvidenceCount = len(in.Signals)
	res.ChannelCount = len(channelSeen)
	res.PageCount = len(pageSeen)
	for ch := range strongSeen {
		res.StrongChannels = append(res.StrongChannels, ch)
	}
	sort.Strings(res.StrongChannels)

	// 2) 基础分。
	base := defaultBaseConfidence
	if in.BaseConf > 0 {
		base = clamp01(float64(in.BaseConf) / 100)
	} else {
		for _, s := range in.Signals {
			if s.BaseConf > 0 {
				base = clamp01(float64(s.BaseConf) / 100)
				break
			}
		}
	}

	// 3) 通道/页面加权。
	strongBonus := math.Min(float64(len(strongSeen))*strongChannelBonus, strongChannelCap)
	mediumBonus := math.Min(float64(len(mediumSeen))*mediumChannelBonus, mediumChannelCap)
	weakBonus := math.Min(float64(len(weakSeen))*weakChannelBonus, weakChannelCap)
	pageBonus := 0.0
	if res.PageCount > 1 {
		pageBonus = math.Min(float64(res.PageCount-1)*extraPageBonus, extraPageCap)
	}
	score := base + strongBonus + mediumBonus + weakBonus + pageBonus
	res.Reasons = append(res.Reasons, fmt.Sprintf(
		"证据 %d 条 / %d 通道 / %d 页（基础 %.2f，通道加权 +%.2f，多页 +%.2f）",
		res.EvidenceCount, res.ChannelCount, res.PageCount, base,
		strongBonus+mediumBonus+weakBonus, pageBonus))
	if len(res.StrongChannels) > 0 {
		res.Reasons = append(res.Reasons, "强通道："+strings.Join(res.StrongChannels, ", "))
	}

	// 4) 同页多指纹冲突降权。
	penalty := 0.0
	conflictPages := collectConflictPages(in.Name, in.Signals, pageTechs)
	if len(conflictPages) > 0 {
		res.Conflict = true
		res.ConflictPages = conflictPages
		for _, page := range conflictPages {
			if hasStrongOnPage(in.Signals, page) {
				penalty += conflictStrongPenalty
			} else {
				penalty += conflictWeakPenalty
			}
		}
		if penalty > conflictPenaltyCap {
			penalty = conflictPenaltyCap
		}
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"同页冲突：%s 同页命中多个技术，降权 -%.2f",
			strings.Join(conflictPages, ", "), penalty))
	}
	score -= penalty

	// 5) 版本交叉校验：不一致 → 降权 + low confidence。
	if !res.VersionCheck.Consistent {
		score -= versionConflictPenalty
		res.LowConfidence = true
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"版本不一致：%s（来源 %s），降权 -%.2f，标记 low confidence",
			strings.Join(res.VersionCheck.Versions, " vs "),
			strings.Join(res.VersionCheck.Sources, " / "),
			versionConflictPenalty))
	} else if res.VersionCheck.Version != "" {
		res.Version = res.VersionCheck.Version
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"版本一致：%s（来源 %s）", res.VersionCheck.Version,
			strings.Join(res.VersionCheck.Sources, " / ")))
	} else {
		res.Reasons = append(res.Reasons, "无版本证据：未做版本交叉校验")
	}

	res.Confidence = roundConfidence(clamp01(score))
	if res.Confidence < 0.5 {
		res.LowConfidence = true
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"置信度 %.2f 低于 0.5，标记 low confidence", res.Confidence))
	}
	return res
}

// collectConflictPages 汇总该技术发生「同页多技术」的页面（升序去重）。
func collectConflictPages(name string, signals []ConfidenceSignal, pageTechs map[string]map[string]bool) []string {
	if len(pageTechs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range signals {
		if s.Page == "" || seen[s.Page] {
			continue
		}
		techs := pageTechs[s.Page]
		if len(techs) < 2 {
			continue
		}
		seen[s.Page] = true
		out = append(out, s.Page)
	}
	sort.Strings(out)
	return out
}

// hasStrongOnPage 该页是否存在强通道证据。
func hasStrongOnPage(signals []ConfidenceSignal, page string) bool {
	for _, s := range signals {
		if s.Page != page {
			continue
		}
		ch := s.Channel
		if ch == "" {
			ch = ChannelOfEvidence(s.Evidence)
		}
		if IsStrongChannel(ch) {
			return true
		}
	}
	return false
}

// ConfidenceBand 置信度分档（high/medium/low），供前端与引擎阈值使用。
func ConfidenceBand(confidence float64) string {
	switch {
	case confidence >= 0.80:
		return "high"
	case confidence >= 0.50:
		return "medium"
	default:
		return "low"
	}
}

// ConfidenceToConf 置信度(0-1) → 既有 Tech.Confidence 口径(0-100)。
// 无证据（0）映射为 0；其余四舍五入且下限 1，避免「有证据但显示 0」。
func ConfidenceToConf(confidence float64) int {
	c := clamp01(confidence)
	if c <= 0 {
		return 0
	}
	conf := int(math.Round(c * 100))
	if conf < 1 {
		conf = 1
	}
	if conf > 100 {
		conf = 100
	}
	return conf
}

// roundConfidence 保留两位小数（确定性输出，避免浮点尾差影响测试/JSON）。
func roundConfidence(v float64) float64 {
	return math.Round(v*100) / 100
}

// clamp01 截断到 [0,1]。
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// containsString 切片包含判定。
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
