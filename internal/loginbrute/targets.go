// 批量目标（LB-02）：串行执行多个目标的登录爆破并汇总。
//
// 语义：
//   - 每目标独立护栏：Options 按目标复制，锁号/连续失败/每账号上限/取消
//     各自计数互不影响；
//   - 批量总量上限：Options.MaxTotalTries > 0 时，跨目标累计尝试数
//     （组合尝试，不含每目标 1 次失败基线）到顶后剩余目标标记为未执行；
//   - 授权白名单逐目标校验：不在 Options.AllowHosts 内的目标零请求拒绝；
//   - 登录模式按 Options.LoginMode 分派：json → JSONBrute，表单 →
//     MultiStep ? BruteMultiStep : Brute。
package loginbrute

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Target 批量爆破目标（LB-02）。
type Target struct {
	URL       string // 站点地址（scheme://host[:port][/path]）
	LoginPath string // 登录页路径（可选：相对路径拼到 URL；绝对 URL 直接使用；空 = URL 本身）
}

// TargetResult 单个目标的爆破结果。
type TargetResult struct {
	Target   Target
	PageURL  string
	Hits     []Hit
	Error    string // 空 = 正常执行；非空 = 被拒绝/中途停止的原因
	Tries    int    // 实际组合尝试数（不含失败基线）
	Duration time.Duration
}

// TargetsResult 批量汇总。
type TargetsResult struct {
	Targets    []TargetResult
	Hits       []Hit // 全部目标命中汇总
	Total      int   // 目标总数
	Failed     int   // 被拒绝（白名单/解析失败）或中途停止的目标数
	Skipped    int   // 未执行的目标数（取消/总量上限）
	Tries      int   // 累计组合尝试数
	StopReason string
}

// BruteTargets 串行执行多个目标的登录爆破并汇总结果（LB-02）。
// 单目标失败不影响后续目标；onProgress 的 done/total 为目标进度，
// msg 带 "[i/n]" 前缀（内含该目标内部的尝试进度文本）。
func BruteTargets(p Poster, opts Options, targets []Target,
	onProgress func(done, total int, msg string)) TargetsResult {
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	res := TargetsResult{
		Targets: make([]TargetResult, 0, len(targets)),
		Hits:    []Hit{},
		Total:   len(targets),
	}
	used := 0 // 已消耗的组合尝试数（跨目标）

	// skipRest 把 from 起的目标全部标记为未执行（取消/总量上限）。
	skipRest := func(from int, reason string) {
		for _, rest := range targets[from:] {
			res.Skipped++
			res.Targets = append(res.Targets, TargetResult{
				Target: rest, PageURL: targetPageURL(rest), Error: "未执行：" + reason,
			})
		}
	}

	for i, t := range targets {
		if opts.Cancel != nil && opts.Cancel() {
			res.StopReason = "已取消"
			skipRest(i, "已取消")
			break
		}
		pageURL := targetPageURL(t)
		onProgress(i, res.Total, fmt.Sprintf("[%d/%d] 开始 %s", i+1, res.Total, pageURL))

		tr := TargetResult{Target: t, PageURL: pageURL}
		start := time.Now()
		// 每目标独立护栏：复制一份 Options，计数器/预算互不影响。
		to := opts
		to.PageURL = pageURL
		if opts.LoginMode == "json" && to.JSONEndpoint != "" {
			to.JSONEndpoint = resolveTargetJSONEndpoint(t, opts.JSONEndpoint)
		}
		// 授权白名单（零请求前置检查）
		if err := checkAllowHosts(&to); err != nil {
			tr.Error = err.Error()
			tr.Duration = time.Since(start)
			res.Failed++
			res.Targets = append(res.Targets, tr)
			onProgress(i+1, res.Total, fmt.Sprintf("[%d/%d] 拒绝：%s", i+1, res.Total, tr.Error))
			continue
		}
		// 批量总量上限：按剩余预算收紧本目标的 MaxTries（Brute 组合预算 = MaxTries-1）。
		if opts.MaxTotalTries > 0 {
			remaining := opts.MaxTotalTries - used
			if remaining <= 0 {
				res.StopReason = "已达批量总量上限（Options.MaxTotalTries）"
				skipRest(i, res.StopReason)
				break
			}
			if to.MaxTries <= 0 {
				to.MaxTries = 300 // 与 Brute/JSONBrute 缺省一致
			}
			if remaining+1 < to.MaxTries {
				to.MaxTries = remaining + 1
			}
			// 至少 1 次基线 + 1 次尝试；remaining>=1 时 MaxTries=2 的预算恰好为 1
			if to.MaxTries < 2 {
				to.MaxTries = 2
			}
		}
		// 统计本目标实际尝试次数：失败尝试（OnFailure 每次失败回调一次）
		// + 命中条数（命中后即停，不再有失败事件）。基线不计入。
		attempts := 0
		userOnFailure := to.OnFailure
		to.OnFailure = func(ev FailureEvent) {
			attempts++
			if userOnFailure != nil {
				userOnFailure(ev)
			}
		}
		inner := func(_ int, _ int, msg string) {
			onProgress(i, res.Total, fmt.Sprintf("[%d/%d] %s", i+1, res.Total, msg))
		}

		var hits []Hit
		var err error
		switch {
		case opts.LoginMode == "json":
			hits, err = JSONBrute(p, to, inner)
		case opts.MultiStep:
			hits, err = BruteMultiStep(p, to, nil, inner)
		default:
			hits, err = Brute(p, to, inner)
		}
		tr.Duration = time.Since(start)
		tr.Hits = hits
		tr.Tries = attempts + len(hits)
		if err != nil {
			tr.Error = err.Error()
			res.Failed++
		}
		res.Tries += tr.Tries
		used += tr.Tries
		res.Hits = append(res.Hits, hits...)
		res.Targets = append(res.Targets, tr)
		onProgress(i+1, res.Total, fmt.Sprintf("[%d/%d] 完成：命中 %d，尝试 %d%s",
			i+1, res.Total, len(hits), tr.Tries, errorSuffix(tr.Error)))
	}
	return res
}

// targetPageURL 解析目标登录页：LoginPath 为空用 URL 本身；绝对 URL 直接
// 使用；相对路径按 Target.URL 解析。
func targetPageURL(t Target) string {
	base := strings.TrimSpace(t.URL)
	lp := strings.TrimSpace(t.LoginPath)
	if lp == "" {
		return base
	}
	bu, err := url.Parse(base)
	if err != nil {
		return lp
	}
	ru, err := url.Parse(lp)
	if err != nil {
		return lp
	}
	return bu.ResolveReference(ru).String()
}

// resolveTargetJSONEndpoint JSON 模式端点随目标走：绝对 URL 原样使用，
// 相对路径按 Target.URL 解析（与页面路径无关，便于批量复用同一模板）。
func resolveTargetJSONEndpoint(t Target, endpoint string) string {
	eu, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || eu.IsAbs() {
		return endpoint
	}
	bu, err := url.Parse(strings.TrimSpace(t.URL))
	if err != nil {
		return endpoint
	}
	return bu.ResolveReference(eu).String()
}

// errorSuffix 进度文案里的错误后缀（空错误不追加）。
func errorSuffix(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return ""
	}
	return "；" + msg
}
