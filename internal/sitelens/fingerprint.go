// Package sitelens 实现证据抽取与指纹匹配（Go 引擎核心）。
package sitelens

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Technology 一条精编指纹（对齐 PG technologies 表）。
type Technology struct {
	Name    string          `json:"name"`
	Cats    []string        `json:"cats"`
	Conf    int             `json:"conf"`
	Website string          `json:"website"`
	Rules   json.RawMessage `json:"rules"`
}

// ruleChannels 指纹规则的证据通道（对齐 Python detectors 字段语义）。
// 兼容两种导出形状：html 为正则数组，或 {dom:[], html:[]} 对象
// （tools/export_intel.py 的历史形状，加载时收敛）。
type ruleChannels struct {
	Headers map[string][]string `json:"headers"` // 响应头名 → 正则组
	Cookies []string            `json:"cookies"` // Cookie 名正则组
	Meta    map[string]string   `json:"meta"`    // meta 名 → 正则
	HTML    []string            `json:"html"`    // HTML 原文正则组
	Scripts struct {
		Src     []string `json:"src"`     // 外链脚本正则组
		Content []string `json:"content"` // 内联脚本正则组
	} `json:"scripts"`
	Dom []string `json:"dom"` // DOM 选择器（暂不实现，保留通道）

	IconHash []int64 `json:"icon_hash"` // FOFA icon_hash（favicon mmh3，见 favicon.go）
}

// unmarshalRules 容错解析规则：整体直解失败时对 html 通道降级重试。
func unmarshalRules(raw json.RawMessage) (*ruleChannels, bool) {
	rc := &ruleChannels{}
	if err := json.Unmarshal(raw, rc); err == nil {
		return rc, true
	}
	// html 通道是 {dom, html} 对象的历史形状
	var loose struct {
		Headers map[string][]string `json:"headers"`
		Cookies []string            `json:"cookies"`
		Meta    map[string]string   `json:"meta"`
		HTML    struct {
			DOM  []string `json:"dom"`
			HTML []string `json:"html"`
		} `json:"html"`
		Scripts struct {
			Src     []string `json:"src"`
			Content []string `json:"content"`
		} `json:"scripts"`
		Dom      []string `json:"dom"`
		IconHash []int64  `json:"icon_hash"`
	}
	if err := json.Unmarshal(raw, &loose); err != nil {
		return nil, false
	}
	rc.Headers = loose.Headers
	rc.Cookies = loose.Cookies
	rc.Meta = loose.Meta
	rc.HTML = loose.HTML.HTML
	rc.Dom = append(loose.Dom, loose.HTML.DOM...)
	rc.Scripts = loose.Scripts
	rc.IconHash = loose.IconHash
	return rc, true
}

// compiledTech 预编译后的单条指纹。
// 纯字面量模式走 strings.Contains 快路径（指纹库大多数模式如此），
// 仅带正则元字符的模式编译为 regexp —— 单页匹配成本的数量级优化。
type compiledTech struct {
	tech       *Technology
	headers    map[string][]pattern
	cookies    []pattern
	meta       map[string]pattern // meta 名 → 预编译正则（带门控，省掉白跑正则）
	html       []pattern
	src        []pattern
	inline     []pattern
	iconHashes []int64
	usable     bool // 至少存在一个可用通道
}

// pattern 字面量或正则的单个匹配模式。
type pattern struct {
	re       *regexp.Regexp // isLit=false 时可用
	gate     string         // isLit=false 时：正则必然包含的最长字面量（小写预筛）
	gateTree *gateNode      // isLit=false 时：正文通道必含字面量条件树（见 gate.go）
	lit      string         // isLit=true 时的小写子串
	raw      string         // 原始文本（证据显示用）
	isLit    bool
}

// compilePats 编译模式组：无正则元字符的按字面量快路径处理；
// 正则模式提取字面量门控（gate），门不命中即跳过正则执行。
// 编译失败的模式跳过不 panic——社区指纹库（千级条目）里个别
// RE2 不支持的形态（反向引用/环视）不该炸掉整个扫描进程。
func compilePats(patterns []string) []pattern {
	return compilePatsMode(patterns, false, nil)
}

// compilePatsMode exact=true 时全部按字面量精确包含处理（EHole 等
// 关键词型社区指纹：关键词含正则元字符也不该按正则解释）。
// intern 非 nil 时按原始 pattern 串复用已编译正则：同一指纹库内 1980 条
// 正则 pattern 实为 1759 条唯一模式，复用 *regexp.Regexp 还能让单次 Match
// 内的正文正则结果缓存跨技术命中（缓存以 *regexp.Regexp 为键）。
func compilePatsMode(patterns []string, exact bool, intern map[string]pattern) []pattern {
	out := make([]pattern, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if exact || isSimpleLiteral(p) {
			out = append(out, pattern{lit: strings.ToLower(p), raw: p, isLit: true})
			continue
		}
		if intern != nil {
			if pat, ok := intern[p]; ok {
				out = append(out, pat)
				continue
			}
		}
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			pat := pattern{re: re, raw: p, gate: literalGate(p)}
			if intern != nil {
				intern[p] = pat
			}
			out = append(out, pat)
		}
	}
	return out
}

func compilePatsLegacy(patterns []string) []pattern {
	out := make([]pattern, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if isSimpleLiteral(p) {
			out = append(out, pattern{lit: strings.ToLower(p), raw: p, isLit: true})
			continue
		}
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			continue
		}
		out = append(out, pattern{re: re, raw: p, gate: literalGate(p)})
	}
	return out
}

func isSimpleLiteral(p string) bool {
	for _, r := range p {
		if strings.ContainsRune(`\.+*?()[]{}|^$`, r) {
			return false
		}
	}
	return true
}

// findIn 在 s（附其小写形态 sLow，避免循环内重复 ToLower 大文本）中匹配，
// 返回 (匹配文本, 捕获组)。字面量无捕获组。
func (p pattern) findIn(s, sLow string) (string, []string) {
	if p.isLit {
		if strings.Contains(sLow, p.lit) {
			return p.raw, nil
		}
		return "", nil
	}
	if p.gate != "" && !strings.Contains(sLow, p.gate) {
		return "", nil // 字面量门控：正则必然含该子串，门不过直接跳过
	}
	m := p.re.FindStringSubmatch(s)
	if m == nil {
		return "", nil
	}
	return m[0], m
}

// literalGate 提取正则中必然出现在匹配结果里的最长字面量运行。
// 保守策略：遇元字符结束当前运行；(…) […] {…} 整段跳过（其中内容
// 不保证逐字出现）；转义字符取字面量。短于 3 字节不设门控。
func literalGate(p string) string {
	var best, cur []byte
	flush := func() {
		if len(cur) > len(best) {
			best = append(best[:0], cur...)
		}
		cur = cur[:0]
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			i++
			if i < len(p) {
				cur = append(cur, p[i])
			}
		case '.', '+', '*', '?', '|', '^', '$', ')':
			flush()
		case '(', '[', '{':
			flush()
			close := byte(')')
			if c == '[' {
				close = ']'
			} else if c == '{' {
				close = '}'
			}
			for i < len(p) && p[i] != close {
				i++
			}
		default:
			cur = append(cur, c)
		}
	}
	flush()
	if len(best) < 3 {
		return ""
	}
	return strings.ToLower(string(best))
}

// Hit 一次指纹命中。
type Hit struct {
	Name     string
	Cats     []string
	Conf     int
	Evidence string
	Version  string
}

// LoadTechnologies 从 JSON 文件加载指纹规则并预编译正则。
func LoadTechnologies(path string) ([]*compiledTech, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadFrom(data)
}

func loadFrom(data json.RawMessage) ([]*compiledTech, error) {
	var box struct {
		Technologies []struct {
			Name    string          `json:"name"`
			Cats    []string        `json:"cats"`
			Conf    int             `json:"conf"`
			Website string          `json:"website"`
			Rules   json.RawMessage `json:"rules"`
			Exact   bool            `json:"exact"`
		} `json:"technologies"`
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return nil, err
	}
	out := make([]*compiledTech, 0, len(box.Technologies))
	// 同库内按原始 pattern 串复用已编译正则（1,980 → 1,759 个 *regexp.Regexp）
	intern := map[string]pattern{}
	// 同串复用门控条件树（语法树解析只在加载期做一次）
	gateCache := map[string]*gateNode{}
	for _, t := range box.Technologies {
		if len(t.Rules) == 0 || t.Name == "" {
			continue
		}
		rules, ok := unmarshalRules(t.Rules)
		if !ok {
			continue // 规则格式不符的指纹跳过，不阻塞加载
		}
		ct := &compiledTech{tech: &Technology{Name: t.Name, Cats: t.Cats, Conf: t.Conf}}
		for name, pats := range rules.Headers {
			if ps := compilePatsMode(pats, t.Exact, intern); len(ps) > 0 {
				if ct.headers == nil {
					ct.headers = make(map[string][]pattern)
				}
				ct.headers[strings.ToLower(unescapeName(name))] = ps
			}
		}
		ct.cookies = compilePatsMode(rules.Cookies, t.Exact, intern)
		for name, p := range rules.Meta {
			if p == "" {
				continue
			}
			if ct.meta == nil {
				ct.meta = make(map[string]pattern)
			}
			// 键名是 meta 名而非正则：反转义历史导出中的 \. \- 序列。
			// 值仍按正则处理（含简单字面量）。门控只用语法树条件树：旧
			// literalGate 会把 `\s`/`\d` 之类转义当字面量字符（WordPress 的
			// `WordPress\s*([\d.]+)?` 会推出 "wordpresss"），而 meta 通道历史上
			// 没有门控，套用旧门会改变判定（实测漏 WordPress）。
			raw := p
			ct.meta[strings.ToLower(unescapeName(name))] = pattern{
				re: regexp.MustCompile("(?i)" + raw), raw: raw,
				gateTree: gateTreeFor(raw, gateCache),
			}
		}
		ct.html = compilePatsMode(rules.HTML, t.Exact, intern)
		ct.src = compilePatsMode(rules.Scripts.Src, false, intern)
		ct.inline = compilePatsMode(rules.Scripts.Content, false, intern)
		// 正文通道（html/inline）正则挂「必含字面量」条件树：加载期推导一次，
		// 匹配期只做字面量存在性判定，避免在 40KB 正文上白跑 NFA。
		attachGateTrees(ct.html, gateCache)
		attachGateTrees(ct.inline, gateCache)
		ct.iconHashes = rules.IconHash
		ct.usable = len(ct.headers) > 0 || len(ct.cookies) > 0 ||
			len(ct.meta) > 0 || len(ct.html) > 0 ||
			len(ct.src) > 0 || len(ct.inline) > 0 || len(ct.iconHashes) > 0
		if ct.usable {
			out = append(out, ct)
		}
	}
	return out, nil
}

// versionFromMatch 捕获组以数字开头才采信为版本号（对齐 Python version_from_match）。
func versionFromMatch(m []string) string {
	if len(m) > 1 && m[1] != "" && m[1][0] >= '0' && m[1][0] <= '9' {
		return m[1]
	}
	return ""
}

// matchCtx 单次 Match 的输入级预筛与缓存：跨全部技术复用，避免同一份证据
// 被重复 ToLower / 重复门控 Contains / 重复执行同一个正则。
type matchCtx struct {
	bodyLow     string                         // 正文小写（Evidence 惰性缓存）
	litHits     map[string]bool                // html 字面量命中集合（nil = 无预筛）
	gateHits    map[string]bool                // 正文通道正则门控命中集合（nil = 无预筛）
	gatePresent func(string) bool              // 正文预筛的字面量存在性判定（nil = 无预筛）
	reCache     map[*regexp.Regexp]regexResult // 正文正则结果缓存（同页同正则只执行一次）
	hdrVal      map[string]string              // 小写头名 → 原始头值（对齐 EqualFold 取头语义）
	hdrLow      map[string]string              // 小写头名 → 小写头值
	hdrList     []headerPair                   // 通配头分支：原始头名/值/小写值
	metaPresent map[string]func(string) bool   // meta 名 → 该 meta 内容的小写字面量存在性判定
}

// headerPair 一个响应头（通配头通道按头遍历用）。
type headerPair struct{ name, val, low string }

// regexResult 一次正文正则执行的结果（text 为空 = 未命中）。
type regexResult struct {
	text string
	subs []string
}

func newMatchCtx(ev *Evidence) *matchCtx {
	mc := &matchCtx{bodyLow: ev.lowerBody()}
	if len(ev.Headers) > 0 {
		mc.hdrVal = make(map[string]string, len(ev.Headers))
		mc.hdrLow = make(map[string]string, len(ev.Headers))
		mc.hdrList = make([]headerPair, 0, len(ev.Headers))
		for k, v := range ev.Headers {
			lk := strings.ToLower(k)
			low := strings.ToLower(v)
			// 同名（大小写不敏感）头只取一个：与旧 EqualFold 遍历取首个的语义对齐
			if _, ok := mc.hdrVal[lk]; !ok {
				mc.hdrVal[lk] = v
				mc.hdrLow[lk] = low
			}
			mc.hdrList = append(mc.hdrList, headerPair{name: k, val: v, low: low})
		}
	}
	if len(ev.Metas) > 0 {
		mc.metaPresent = make(map[string]func(string) bool, len(ev.Metas))
		for name, content := range ev.Metas {
			low := strings.ToLower(content)
			mc.metaPresent[name] = func(lit string) bool { return strings.Contains(low, lit) }
		}
	}
	return mc
}

// findBodyPattern 在正文中匹配单个模式：字面量走 Contains；正则走单次 Match
// 内的结果缓存（同一 *regexp.Regexp 在同一份正文上只执行一次，加载期已按
// 原始 pattern 串 intern，重复 pattern 共享同一 *regexp.Regexp）。
func (mc *matchCtx) findBodyPattern(p pattern, body string) (string, []string) {
	if p.isLit || p.re == nil {
		return p.findIn(body, mc.bodyLow)
	}
	if r, ok := mc.reCache[p.re]; ok {
		return r.text, r.subs
	}
	text, subs := p.findIn(body, mc.bodyLow)
	if mc.reCache == nil {
		mc.reCache = make(map[*regexp.Regexp]regexResult, 8)
	}
	mc.reCache[p.re] = regexResult{text: text, subs: subs}
	return text, subs
}

// Match 对已采集证据应用全部指纹，返回命中列表。
// 通道语义与 Python 版一致：通道内任一正则命中即该通道成立；
// 单条指纹声明多个通道时，全部通道命中才算命中（AND）。
func Match(techs []*compiledTech, ev *Evidence) []Hit {
	hits := make([]Hit, 0, 8)
	mc := newMatchCtx(ev)
	for _, ct := range techs {
		if evName, evVer, ok := ct.match(ev, mc); ok {
			hits = append(hits, Hit{
				Name: ct.tech.Name, Cats: ct.tech.Cats, Conf: ct.tech.Conf,
				Evidence: evName, Version: evVer,
			})
		}
	}
	return hits
}

// MatchPrescreen 带字面量预筛的匹配：对全部 html 字面量模式做一次
// 前缀桶单遍扫描（O(正文长度)），逐技术改为查表——万级指纹库下把
// 「模式数 × 正文长度」的 Contains 总量压成一次正文扫描。
// 正则门控字面量并入同一次扫描（gateHits）：门不命中即跳过正则，
// 等价于旧实现在正文小写上的逐正则 strings.Contains。
func MatchPrescreen(techs []*compiledTech, ev *Evidence, ps *litPrescreen) []Hit {
	hits := make([]Hit, 0, 8)
	mc := newMatchCtx(ev)
	if ps != nil && len(ps.buckets) > 0 {
		mc.litHits, mc.gateHits = ps.scan(mc.bodyLow)
		mc.gatePresent = func(lit string) bool { return mc.gateHits[lit] }
	}
	for _, ct := range techs {
		if evName, evVer, ok := ct.match(ev, mc); ok {
			hits = append(hits, Hit{
				Name: ct.tech.Name, Cats: ct.tech.Cats, Conf: ct.tech.Conf,
				Evidence: evName, Version: evVer,
			})
		}
	}
	return hits
}

// match 按通道顺序应用证据；返回 (证据描述, 版本, 是否命中)。
// mc 为单次 Match 共享的正文级上下文（小写正文 / 字面量预筛 / 正则结果缓存）。
func (ct *compiledTech) match(ev *Evidence, mc *matchCtx) (string, string, bool) {
	if len(ct.headers) > 0 {
		for name, pats := range ct.headers {
			if name == "*" {
				// 通配任意头：EHole 等社区指纹的 header 规则不带头名，
				// 关键词对全部头值做包含判定（只支持字面量语义）。
				// 同样要求强关键词命中：如 must-revalidate / no-cache 之类
				// 通用缓存头值不构成产品识别依据（曾把 SAMSUNG-SNB-2000
				// 判在无关联的站点上）。
				for _, hp := range mc.hdrList {
					if hp.val == "" {
						continue
					}
					for _, p := range pats {
						if p.isLit && strings.Contains(hp.low, p.lit) && !weakKeyword(p.raw) {
							return fmt.Sprintf("%s=%s", hp.name, truncate(hp.val, 80)), "", true
						}
					}
				}
				continue
			}
			val := mc.hdrVal[name]
			if val == "" {
				continue
			}
			valLow := mc.hdrLow[name]
			for _, p := range pats {
				if text, subs := p.findIn(val, valLow); text != "" {
					return fmt.Sprintf("%s=%s", name, truncate(val, 80)),
						versionFromMatch(subs), true
				}
			}
		}
	}
	if len(ct.cookies) > 0 {
		for _, p := range ct.cookies {
			for _, cn := range ev.CookieNames {
				if text, subs := p.findIn(cn, cn); text != "" {
					return fmt.Sprintf("cookie %s", cn), versionFromMatch(subs), true
				}
			}
		}
	}
	if len(ct.meta) > 0 {
		for metaName, p := range ct.meta {
			content := ev.Metas[metaName]
			if content == "" {
				continue
			}
			// 必含字面量门控：meta 内容短，但万级指纹逐条执行正则的机器开销
			// 不小；门控只做字面量存在性判定，结果与执行正则一致。
			if p.gateMiss(mc.metaPresent[metaName]) {
				continue
			}
			if m := p.re.FindStringSubmatch(content); m != nil {
				return fmt.Sprintf("meta %s=%s", metaName,
					truncate(content, 60)), versionFromMatch(m), true
			}
		}
	}
	if len(ct.html) > 0 || len(ct.inline) > 0 {
		// 字面量关键词通道（EHole 类社区指纹）有双重闸门：
		//
		// ① 弱证据过滤：keyword 的全部语义 token 都是通用词/低熵短串
		//    （login / url / oa / 360 …）时不足以识别产品，只记待定；
		//    实测 DVWA 单站曾被判 58 项技术，54 项假阳性。
		//
		// ② 单关键词佐证要求：EHole 指纹是「任一关键词命中即算」的 OR 语义，
		//    而**产品名本身**（VMware / Consul / MacOS）常出现在无关页面的
		//    讨论、下载清单或部署文档里——DVWA 首页 README 提了一次
		//    "VMware"，就把站点判成 VMware Horizon/vCenter/vRealize 四项。
		//    故：唯一命中的关键字若只是**产品名形态**（无路径 / 域名 / 版本 /
		//    复合词等高区分度特征），要求同一指纹的**第二个不同关键词**也命中
		//    才算识别；否则只记待定。
		var fallback string // 弱命中或产品名单命中：有更强证据才采信
		strongSeen := []string{}
		for _, p := range ct.html {
			if p.isLit && mc.litHits != nil {
				// 预筛已含该字面量才可能命中，省掉逐技术 Contains
				if !mc.litHits[p.lit] {
					continue
				}
				desc := fmt.Sprintf("关键词 %s", truncate(p.raw, 40))
				if weakKeyword(p.raw) {
					if fallback == "" {
						fallback = desc
					}
					continue
				}
				if productNameOnly(p.raw) {
					strongSeen = appendUnique(strongSeen, p.raw)
					if fallback == "" {
						fallback = desc
					}
					continue // 产品名单关键词需第二个佐证
				}
				return desc, "", true
			}
			// 正文通道正则的必含字面量门控（旧最长字面量门 + 语法树条件）：
			// 条件确定不成立即可跳过，等价于执行正则后必然不命中。
			if !p.isLit && p.gateMiss(mc.gatePresent) {
				continue
			}
			if text, subs := mc.findBodyPattern(p, ev.Body); text != "" {
				return fmt.Sprintf("正则 %s", truncate(p.raw, 40)),
					versionFromMatch(subs), true
			}
		}
		// 两个及以上不同产品名单关键词命中 → 互相佐证，采信
		if len(strongSeen) >= 2 {
			return fmt.Sprintf("关键词 %s", truncate(strongSeen[0], 40)), "", true
		}
		_ = fallback // 仅弱/单条产品名证据不足以识别，继续其它通道
		if len(ct.src) > 0 {
			for _, p := range ct.src {
				for _, src := range ev.ScriptSrcs {
					if text, subs := p.findIn(src, src); text != "" {
						return fmt.Sprintf("src %s", truncate(src, 80)),
							versionFromMatch(subs), true
					}
				}
			}
		}
		if len(ct.inline) > 0 {
			for _, p := range ct.inline {
				if !p.isLit && p.gateMiss(mc.gatePresent) {
					continue
				}
				if text, subs := mc.findBodyPattern(p, ev.Body); text != "" {
					return fmt.Sprintf("内联JS %s", truncate(text, 40)),
						versionFromMatch(subs), true
				}
			}
		}
	}
	// icon_hash 通道：favicon mmh3 指纹（0 = 未采集，不参与匹配）
	if len(ct.iconHashes) > 0 && ev.FaviconHash != 0 {
		for _, h := range ct.iconHashes {
			if h == ev.FaviconHash {
				return fmt.Sprintf("icon_hash=%d", ev.FaviconHash), "", true
			}
		}
	}
	return "", "", false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// unescapeName 反转义规则键名中的常见正则转义（\. \-），用于 meta/头名匹配。
func unescapeName(s string) string {
	s = strings.ReplaceAll(s, `\.`, ".")
	s = strings.ReplaceAll(s, `\-`, "-")
	return s
}
