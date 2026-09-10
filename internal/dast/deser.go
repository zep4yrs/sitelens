// 反序列化入口面探测（低危面信号，非漏洞确认）：
// 注入 Java 序列化魔数（aced0005）的 URL 编码形态，响应出现反序列化
// 报错特征即提示该参数可能进入反序列化处理链。判定保守：只认具体的
// 序列化异常类名，普通报错不报。
package dast

import "strings"

// deserMarkers Java 反序列化处理链的报错特征（出现即说明走了反序列化路径）。
var deserMarkers = []string{
	"StreamCorruptedException",
	"InvalidClassException",
	"InvalidObjectException",
	"java.io.EOFException",
	" org.hibernate.InstantiationException",
}

func (r *Runner) deserProbe(tgt Target, done *int, total int) *Finding {
	u := setParam(tgt.URL, tgt.Param, "%AC%ED%00%05sl")
	if len(u) > r.opts.MaxURLLen {
		return nil
	}
	resp := r.fetch.GetSmall(u)
	*done++
	if r.prog != nil {
		r.prog(*done, total, shortLabel(tgt))
	}
	if resp == nil {
		return nil
	}
	for _, marker := range deserMarkers {
		if strings.Contains(resp.Body, marker) {
			return &Finding{
				Check:    "deser-surface",
				Title:    "疑似 Java 反序列化入口（报错特征）",
				Severity: "low",
				URL:      tgt.URL,
				Param:    tgt.Param,
				Payload:  "%AC%ED%00%05sl",
				Evidence: "响应出现序列化处理链特征：" + marker,
				Replay:   curlReplay(u),
				Advice:   "确认该入口是否对用户输入做反序列化；优先白名单校验与签名机制",
			}
		}
	}
	return nil
}
