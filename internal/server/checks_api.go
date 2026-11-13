package server

// 内置验证 check 元数据 API（5.3.1）：只读，供 UI/Agent/审计查看
// 每条 check 的 ATT&CK / 噪声 / 安全等级与归类依据。

import (
	"net/http"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

// hChecks GET /api/checks 返回全量内置验证 check 及元数据。
func (s *Server) hChecks(w http.ResponseWriter, r *http.Request) {
	all := checks.AllChecks()
	list := make([]map[string]any, 0, len(all))
	for _, c := range all {
		m := checks.MetaOf(c)
		list = append(list, map[string]any{
			"id": c.ID, "lv": c.Lv, "path": c.Path, "title": c.Title,
			"severity": c.Sev, "attack": m.ATTACK, "noise": m.Noise,
			"safety": m.Safety, "reason": m.Reason,
		})
	}
	writeJSON(w, 200, map[string]any{
		"checks": list, "count": len(list),
		"note": "内置验证集为 GET+静态路径的只读探测；ATT&CK 为检测视角映射，不代表执行了对应攻击技术。",
	})
}
