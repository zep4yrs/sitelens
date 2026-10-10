// 上传绕过验证通道：对文件上传表单做「扩展名/内容类型黑名单绕过」判定，
// 而不是只报「存在上传受理面」。
//
// 为什么需要这条通道：upload-surface 只证明「服务端收下了无害 .txt」，
// 这是一句没有攻击含义的话——任何正常上传功能都这样。真正的漏洞形态是
// 「服务端收下了本该拒绝的可执行扩展名」。upload-labs 全部 21 关考的都是
// 这个，此前引擎整块进不来。
//
// 判定语义（非破坏性，只做「受理/拒绝」二值判定）：
//  1. 先建立基线：无害扩展名（.jpg）提交，必须被受理——否则该表单不可用，
//     整表放弃（避免把「拒绝一切」的静态网关当作绕过）。
//  2. 逐个提交危险扩展名（同一份无害文本内容），出现受理信号即判定
//     黑名单未覆盖该扩展名 —— 「扩展名黑名单绕过」。
//  3. 内容类型绕过：危险扩展名 + 伪造 image/png Content-Type 组合被受理。
//  4. 双扩展名 / 尾随字符形态：.php.jpg、.php%00.jpg、.php::$DATA、.phtml 等。
//
// 提交内容始终是唯一标记的无害文本，不含任何可执行代码；判定只看服务端
// 「收没收」，不落地文件、不尝试执行。误报防线：拒绝特征优先于受理特征。
package dast

import "strings"

// uploadBypassExts 危险扩展名候选（对应常见黑名单遗漏项）。
// 顺序即提交顺序：先最经典的 .php，再各类同义/别名/容器变体。
var uploadBypassExts = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".phar",
	".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cer", ".asa", ".cdx",
	".shtml", ".shtm", ".htaccess", ".svg", ".hta",
}

// uploadBypassCt 内容类型伪造候选（服务端只查 Content-Type 时常绕过）。
const uploadBypassCt = "image/png"

// uploadBypassSuffixes 双扩展名 / 截断 / 尾随形态。
var uploadBypassSuffixes = []string{
	".php.jpg", ".php.png", ".php%00.jpg", ".php\x00.jpg", ".php::$DATA",
	".php.", ".php%20", ".pHp", ".PHP", ".phtml.jpg",
}

// uploadBypassProbe 单表单的上传绕过验证。返回命中列表（可能多条）。
func (r *Runner) uploadBypassProbe(ft FormTarget, fileField string, extra map[string]string) []Finding {
	if fileField == "" || r.stopped() {
		return nil
	}
	// 基线：无害扩展名。不被受理 → 该表单不是可用的上传点（或网关全拒），放弃。
	base := r.fetch.PostMultipartSmall(ft.Action, fileField, "sl_base.jpg", uploadProbeMarker, extra)
	if base == nil || !uploadAccepted(base) {
		return nil
	}

	var out []Finding
	seen := map[string]bool{}
	attempt := func(fname, ct, kind, why string) {
		key := fname + "\x00" + ct
		if r.stopped() || seen[key] {
			return
		}
		seen[key] = true
		ctf, ok := r.fetch.(MultipartCTFetcher)
		if !ok {
			return // 不支持自定义 Content-Type 的上传：跳过，不误报
		}
		resp := ctf.PostMultipartSmallCT(ft.Action, fileField, fname, uploadProbeMarker, ct, extra)
		if resp == nil || !uploadAccepted(resp) {
			return
		}
		f := Finding{
			Check: "upload-bypass", Title: "文件上传扩展名/类型绕过（" + kind + "）",
			Severity: "high", URL: ft.Action, Param: fileField, Payload: fname,
			Evidence: "基线 .jpg 被受理；提交 " + fname + "（Content-Type: " + ct +
				"）同样被受理 —— " + why + "。判定依据：" + uploadAcceptReason(resp) +
				"；提交内容为无害文本标记，未含可执行代码。",
			Advice: "扩展名白名单化（服务端解析结果为准，非文件名后缀）+ 内容魔数校验 + " +
				"落盘目录禁用脚本执行（php-fpm/cgi 隔离）+ 文件名归一化（去 %00 / ::$DATA / 多扩展名）。",
			Impact: "可上传服务端可解析的脚本文件，进而获得命令执行能力。",
		}
		f.Request = "POST " + ft.Action + " HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\n" +
			"(文件字段 " + fileField + " = " + fname + ", " + ct + "，内容为无害探针标记)"
		f.Response = &RespSnap{Status: resp.Status, Size: len(resp.Body), Snippet: snippetOf(resp.Body)}
		f.Signals = []string{"基线受理：.jpg", "绕过受理：" + fname, "判定信号：" + uploadAcceptReason(resp)}
		if r.opts.OnHit != nil {
			r.opts.OnHit(f)
		}
		out = append(out, f)
	}

	cap := r.opts.MaxProbesPerClass
	if cap <= 0 {
		cap = 12
	}
	n := 0
	// 1) 危险扩展名 + 伪造图片 Content-Type（只查 MIME 的目标）——
	// 先跑，因为它是命中率最高、成本最低的一条。
	if n < cap {
		attempt("sl_probe.php", uploadBypassCt, "仅校验 Content-Type",
			"危险扩展名配伪造 image/png 类型未被拒绝")
		n++
	}
	// 2) 危险扩展名原样提交（黑名单遗漏）。
	for _, ext := range uploadBypassExts {
		if n >= cap {
			break
		}
		attempt("sl_probe"+ext, "application/octet-stream", "扩展名黑名单未覆盖",
			"危险扩展名 "+ext+" 未被拒绝")
		n++
	}
	// 3) 双扩展名 / 截断 / 大小写形态。
	for _, sfx := range uploadBypassSuffixes {
		if n >= cap {
			break
		}
		attempt("sl_probe"+sfx, "application/octet-stream", "文件名归一化缺失",
			"变体文件名 "+sfx+" 未被拒绝")
		n++
	}
	return out
}

// uploadAccepted 上传被受理判定（拒绝特征优先）。
func uploadAccepted(resp *Resp) bool {
	return uploadAcceptReason(resp) != ""
}

// uploadAcceptReason 返回受理信号说明（空串 = 未受理）。
func uploadAcceptReason(resp *Resp) string {
	if resp == nil {
		return ""
	}
	low := strings.ToLower(resp.Body)
	for _, m := range uploadRejectMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return ""
		}
	}
	for _, m := range uploadAcceptMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return "命中受理特征 " + m
		}
	}
	if strings.Contains(resp.Body, uploadProbeMarker) {
		return "响应回显上传文件内容标记"
	}
	return ""
}
