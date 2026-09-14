// 黑盒结果结构化收集器（P2）。
//
// collector 在 Scan 的各阶段把瞬时产物（入口/发现/证据/影响）规整为
// internal/model 的实体，挂到 Result.Graph 上。设计约束（开发文档第 6 节）：
//
//   - 只在 opts.Graph 开启时工作（默认关）——不开则完全等同 3.0 行为；
//   - 不触碰 res.Verified 的 map 形态与键位（3.0 JSON 逐字节不变）；
//   - 证据是信任根：vuln_node / chain 只能引用已入图的 evidence；
//   - 观测态诚实：只有真实命中才 positive；无证据的关系不得 confirmed。
package engine

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/dast"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/jsmap"
	"cnb.cool/feng-qiao/sitelens/internal/loginbrute"
	"cnb.cool/feng-qiao/sitelens/internal/model"
	"cnb.cool/feng-qiao/sitelens/internal/modules"
	"cnb.cool/feng-qiao/sitelens/internal/passive"
)

// collector 单次扫描的黑盒实体收集器。
type collector struct {
	g *model.ScanGraph
	// techs 供 intel 关联时补指纹证据（技术名 → 指纹证据串）。
	techs []Tech
}

// newCollector 创建收集器（scannedAt 作为图的生成时间）。
func newCollector(scannedAt string) *collector {
	g := model.NewGraph("")
	g.GeneratedAt = scannedAt
	return &collector{g: g}
}

// graph 返回收集完成的图。
func (c *collector) graph() *model.ScanGraph { return c.g }

// ev 构造并加入一条证据，返回其稳定 ID（空内容返回空串，不产生空证据）。
func (c *collector) ev(kind, source, rawURL, file string, line int, body string) string {
	if body == "" {
		return ""
	}
	e := model.NewEvidence(kind, model.OriginBlackbox, source, c.g.ScanID, rawURL, file, line, body)
	c.g.Add(e)
	return e.ID
}

// addEvidence 追加非空证据 ID（过滤空串，保持顺序）。
func addEv(list []string, ids ...string) []string {
	for _, id := range ids {
		if id != "" {
			list = append(list, id)
		}
	}
	return list
}

// ---- 入口点收集（阶段 2/3/8）----

// captureEntryPoints 收集爬取与 JS 提取出的入口点（不带证据也要建，
// 因为它们是攻击面事实；证据在发现命中时补挂）。
func (c *collector) captureEntryPoints(paramLinks []string, forms []dast.FormTarget, jsEndpoints []jsmap.Endpoint) {
	for _, l := range paramLinks {
		c.addURLEntry(l, "GET", nil)
	}
	for _, f := range forms {
		c.addFormEntry(f.Action, f.Fields, nil)
	}
	for _, ep := range jsEndpoints {
		c.addJSEndpoint(ep)
	}
}

// addURLEntry 为带参 URL 建入口点：每个查询参数一个 param 入口（ID 用
// 路径而非带值 URL，保证同名参数不同取值只产生一个入口）。
// 返回首个入口点 ID（供 vuln_node 的 entry_id 引用）。
func (c *collector) addURLEntry(rawURL, method string, ev []string) string {
	base, params := splitURL(rawURL)
	if len(params) == 0 {
		ep := model.NewEntryPoint(model.OriginBlackbox, "url", base, method, "", "", "", ev)
		ep.URL = rawURL
		c.g.Add(ep)
		return ep.ID
	}
	first := ""
	for _, p := range params {
		ep := model.NewEntryPoint(model.OriginBlackbox, "param", base, method, p, "", "", ev)
		ep.URL = rawURL
		c.g.Add(ep)
		if first == "" {
			first = ep.ID
		}
	}
	return first
}

// addParamEntry 为已知参数建入口点（DAST 命中时定位更精确）。
func (c *collector) addParamEntry(rawURL, param, method string, ev []string) string {
	base, _ := splitURL(rawURL)
	ep := model.NewEntryPoint(model.OriginBlackbox, "param", base, method, param, "", "", ev)
	ep.URL = rawURL
	c.g.Add(ep)
	return ep.ID
}

// addFormEntry 为表单建入口点。
func (c *collector) addFormEntry(action string, fields []string, ev []string) string {
	base, _ := splitURL(action)
	ep := model.NewEntryPoint(model.OriginBlackbox, "form", base, "POST", "", "", "", ev)
	ep.URL = action
	ep.Params = append([]string(nil), fields...)
	c.g.Add(ep)
	return ep.ID
}

// addJSEndpoint 为 JS 提取的端点建入口点。
func (c *collector) addJSEndpoint(ep jsmap.Endpoint) {
	base, _ := splitURL(ep.Endpoint)
	e := model.NewEntryPoint(model.OriginBlackbox, "js_endpoint", base, "GET", "", "", "", nil)
	e.URL = ep.Endpoint
	c.g.Add(e)
}

// ---- 发现收集（阶段 6/6.5/7/8）----

// addCheckHit 收集一条验证型 check / nuclei 命中（src 区分来源）。
func (c *collector) addCheckHit(h checks.Hit, src string) {
	var evs []string
	evs = addEv(evs,
		c.ev("request", src, h.URL, "", 0, h.Request),
		c.ev("replay", src, h.URL, "", 0, h.Replay),
	)
	if h.Response != nil {
		evs = addEv(evs, c.ev("response", src, h.URL, "", 0, snapBody(h.Response.Status, h.Response.Size, h.Response.Snippet)))
	}
	if len(h.Signals) > 0 {
		evs = addEv(evs, c.ev("signals", src, h.URL, "", 0, strings.Join(h.Signals, "\n")))
	}
	conf := model.ConfProbable
	if h.Confirmed {
		conf = model.ConfConfirmed
	}
	entryID := c.addURLEntry(h.URL, "GET", evs)
	vn := model.NewVulnNode(model.OriginBlackbox, h.Check, "", h.URL, "", "", 0,
		model.ObsPositive, "detected", conf, evs)
	vn.Title, vn.Severity, vn.EntryID = h.Title, h.Severity, entryID
	vn.CWEs = CWEForCheck(h.Check)
	c.g.Add(vn)
	c.attachCWE(vn.ID, vn.CWEs, evs)
}

// addSimpleFinding 收集 passive / jsmap 这类同构发现
// （check/title/severity/url/evidence 五字段；advice 属 3.0 map 展示层，
// 模型层不承载）。
func (c *collector) addSimpleFinding(check, title, severity, rawURL, evidenceText, advice, src string) {
	var evs []string
	if evidenceText != "" {
		evs = addEv(evs, c.ev("snippet", src, rawURL, "", 0, evidenceText))
	}
	entryID := c.addURLEntry(rawURL, "GET", evs)
	vn := model.NewVulnNode(model.OriginBlackbox, check, "", rawURL, "", "", 0,
		model.ObsPositive, "detected", model.ConfProbable, evs)
	vn.Title, vn.Severity, vn.EntryID = title, severity, entryID
	vn.CWEs = CWEForCheck(check)
	c.g.Add(vn)
	c.attachCWE(vn.ID, vn.CWEs, evs)
}

// addPassiveHit 收集被动检测命中。
func (c *collector) addPassiveHit(h passive.Hit) {
	c.addSimpleFinding(h.Check, h.Title, h.Severity, h.URL, h.Evidence, h.Advice, "passive")
}

// addJSFinding 收集 JS 攻击面发现。
func (c *collector) addJSFinding(f jsmap.Finding) {
	c.addSimpleFinding(f.Check, f.Title, f.Severity, f.URL, f.Evidence, f.Advice, "js")
}

// addDASTFinding 收集 DAST 命中，并挂 exploit 回填的 impact。
func (c *collector) addDASTFinding(f dast.Finding, m map[string]any) {
	var evs []string
	evs = addEv(evs,
		c.ev("payload", "dast", f.URL, "", 0, f.Payload),
		c.ev("request", "dast", f.URL, "", 0, f.Request),
		c.ev("replay", "dast", f.URL, "", 0, f.Replay),
	)
	if f.Response != nil {
		evs = addEv(evs, c.ev("response", "dast", f.URL, "", 0, snapBody(f.Response.Status, f.Response.Size, f.Response.Snippet)))
	}
	if len(f.Signals) > 0 {
		evs = addEv(evs, c.ev("signals", "dast", f.URL, "", 0, strings.Join(f.Signals, "\n")))
	}
	entryID := c.addParamEntry(f.URL, f.Param, "GET", evs)
	vn := model.NewVulnNode(model.OriginBlackbox, f.Check, "", f.URL, f.Param, "", 0,
		model.ObsPositive, "detected", model.ConfConfirmed, evs)
	vn.Title, vn.Severity, vn.EntryID = f.Title, f.Severity, entryID
	vn.CWEs = CWEForCheck(f.Check)
	c.g.Add(vn)
	c.attachCWE(vn.ID, vn.CWEs, evs)

	// exploit 层回填：impact（影响证明）+ impact_evidence。
	impactVerdict, hasImpact := mapStr(m, "impact")
	if !hasImpact || impactVerdict == "" || impactVerdict == "none" {
		return
	}
	ievs := evs
	if txt, ok := mapStr(m, "impact_evidence"); ok && txt != "" {
		ievs = addEv(append([]string(nil), evs...), c.ev("impact", "exploit", f.URL, "", 0, txt))
	}
	im := model.NewImpact(impactKindForCheck(f.Check), impactVerdict, vn.ID, "", nil,
		model.ConfProbable, ievs)
	c.g.Add(im)

	// P7：exploit 已证明的影响 → 权限变化原料（mechanism=exploit-proven）。
	// 只有 proven/observed 才建（none 上面已 return），不臆造提权终点。
	pc := model.NewPrivChange("anonymous", privTargetForImpact(impactVerdict),
		"exploit-proven", vn.ID, model.ConfProbable, ievs)
	c.g.Add(pc)
}

// privTargetForImpact 把影响判定映射为「权限变化终点」标签。
// proven 才视为确实达成该影响；observed 仅标记为「疑似可达」。
func privTargetForImpact(verdict string) string {
	if verdict == "proven" {
		return "impact-reached"
	}
	return "impact-suspected"
}

// addDirBypass 收集 403 绕过命中 → priv_change（P7：完整机制语义）。
//
// 语义：匿名访问本应被拒绝的资源却成功 → 访问控制失效（不是提权到某角色，
// 故 to 记为 restricted-resource，不臆造 admin）。
func (c *collector) addDirBypass(h modules.PageHit) {
	if h.Bypass == "" {
		return // 未绕过：不是访问控制失效，不产 priv_change
	}
	body := fmt.Sprintf("path=%s status=%d size=%d bypass=%s", h.Path, h.Status, h.Size, h.Bypass)
	evID := c.ev("response", "modules", h.URL, "", 0, body)
	if evID == "" {
		return
	}
	// 以被绕过路径的入口点作为 finding 锚（保证 fig 可追溯且 ID 不碰撞）。
	anchor := c.addURLEntry(h.URL, "GET", []string{evID})
	pc := model.NewPrivChange("anonymous", "restricted-resource", "bypass-403", anchor,
		model.ConfProbable, []string{evID})
	c.g.Add(pc)
}

// addWeakCredential 收集弱口令命中 → priv_change（mechanism=credential）。
//
// 语义：匿名者凭泄露/弱口令获得认证态。to 记 authenticated（不臆断为 admin——
// 除非命中用户名字面即为 root/admin，那也只是「疑似高权」，用 suspected-admin 标注）。
func (c *collector) addWeakCredential(h loginbrute.Hit) {
	body := fmt.Sprintf("type=%s user=%s url=%s", h.Type, h.User, h.URL)
	evID := c.ev("response", "loginbrute", h.URL, "", 0, body)
	if evID == "" {
		return
	}
	anchor := c.addURLEntry(h.URL, "GET", []string{evID})
	to := "authenticated"
	if isHighPrivUser(h.User) {
		to = "suspected-admin"
	}
	pc := model.NewPrivChange("anonymous", to, "credential", anchor,
		model.ConfConfirmed, []string{evID})
	c.g.Add(pc)
}

// isHighPrivUser 判断命中用户名是否像高权账号（仅用于标注，不据此断言提权）。
func isHighPrivUser(user string) bool {
	switch strings.ToLower(strings.TrimSpace(user)) {
	case "root", "admin", "administrator", "sa", "system":
		return true
	}
	return false
}

// annotateImpactPriors 为图内 impact 补 KEV/CVSS 先验标注（P7）。
// **仅作解释**：priors 不参与建链（chain 不消费该字段）。
// 数据来源：NVD（CVSS）+ KEV 清单；缺数据时不动（不臆造）。
func (c *collector) annotateImpactPriors(cveOf map[string]string, kevOf map[string]bool, cvssOf map[string]float64) {
	for i := range c.g.Impacts {
		im := &c.g.Impacts[i]
		cve := cveOf[im.VulnID]
		if cve == "" {
			continue
		}
		var priors []string
		if kevOf[strings.ToUpper(cve)] {
			priors = append(priors, "kev")
		}
		if s := cvssOf[strings.ToUpper(cve)]; s > 0 {
			priors = append(priors, fmt.Sprintf("cvss:%.1f", s))
		}
		if len(priors) > 0 {
			im.Priors = priors
		}
	}
}

// addIntelFinding 收集情报关联结论。指纹命中即为它的证据来源；
// confirmed（版本区间命中）→ positive + probable，possible → unknown + possible。
// 情报是提示而非利用验证，故不给 confirmed 置信级（诚实分级）。
func (c *collector) addIntelFinding(f intel.Finding) {
	var evs []string
	for _, t := range c.techs {
		if !strings.EqualFold(t.Name, f.Tech) {
			continue
		}
		for _, e := range t.Evidence {
			evs = addEv(evs, c.ev("fingerprint", "fingerprint", "", "", 0, t.Name+"："+e))
		}
	}
	obs, conf := model.ObsUnknown, model.ConfPossible
	if f.Verdict == "confirmed" {
		obs, conf = model.ObsPositive, model.ConfProbable
	}
	// CVE 进 checkID 参与 ID：同一情报源的不同 CVE 必须是不同节点。
	checkID := "intel:" + f.Src
	if f.CVE != "" {
		checkID += ":" + f.CVE
	}
	vn := model.NewVulnNode(model.OriginBlackbox, checkID, "", "", "", "", 0, obs, f.Verdict, conf, evs)
	vn.Title, vn.Severity, vn.CVE = f.Title, f.Severity, f.CVE
	c.g.Add(vn)
}

// captureTechs 记录已识别技术（intel 关联时补指纹证据用）。
func (c *collector) captureTechs(techs []Tech) { c.techs = techs }

// ---- 内部辅助 ----

// attachCWE 为漏洞节点挂 CWE 关联（有 finding 证据 → probable）。
func (c *collector) attachCWE(vulnID string, cwes []string, ev []string) {
	for _, cwe := range cwes {
		c.g.Add(model.NewCWERel(model.KindVulnNode, vulnID, cwe, "mapping",
			model.ConfProbable, ev))
	}
}

// snapshot 某响应的证据正文（状态/长度/摘要），保证可读且可复现。
func snapBody(status, size int, snippet string) string {
	return fmt.Sprintf("status=%d size=%d\n%s", status, size, snippet)
}

// mapStr 从 verified map 安全取字符串值。
func mapStr(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}

// splitURL 把 URL 拆为「scheme://host/path」基址 + 排序去重后的参数名列表。
// 参数名参与入口点 ID，故排序保证不同参数顺序产生同一 ID。
func splitURL(rawURL string) (base string, params []string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, nil
	}
	base = u.Scheme + "://" + u.Host + u.Path
	seen := map[string]bool{}
	for k := range u.Query() {
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		params = append(params, k)
	}
	sort.Strings(params)
	return base, params
}

// nvdLookup 把 *intel.KB 的 NVD 索引适配为 cwe.NVDLookup（P5）。
// 在单独文件中以避免 entities.go 顶部 import 面扩大。
type nvdLookup struct{ kb *intel.KB }

// CWEsFor 查 CVE 的 CWE（无挂载/无数据返回 nil）。
func (n nvdLookup) CWEsFor(cve string) []string {
	if n.kb == nil {
		return nil
	}
	s := n.kb.NVD()
	if s == nil {
		return nil
	}
	return s.CWEsFor(cve)
}
