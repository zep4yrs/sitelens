package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/apispec"
	"cnb.cool/feng-qiao/sitelens/internal/target"
)

// hAPISpec 解析上传的 API 描述（OpenAPI 3 / Swagger 2 JSON、HAR 1.2），
// 返回端点/参数/类型清单，供后续 DAST/API 扫描使用。纯解析，不发起请求。
func (s *Server) hAPISpec(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, apispec.MaxInputBytes+1))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "读取请求体失败"})
		return
	}
	if len(body) > apispec.MaxInputBytes {
		writeJSON(w, 413, map[string]any{"error": "描述文件超过 8MB 上限"})
		return
	}
	fmtKind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("fmt")))
	if fmtKind == "" {
		fmtKind = "auto"
	}
	var spec *apispec.Spec
	switch fmtKind {
	case "har":
		spec, err = apispec.ParseHAR(body)
	case "openapi", "swagger":
		spec, err = apispec.ParseOpenAPI(body)
	default:
		// auto：先按 JSON 判断是否 HAR（含 log.entries）再按 OpenAPI。
		var probe struct {
			Log *struct {
				Entries []json.RawMessage `json:"entries"`
			} `json:"log"`
		}
		if json.Unmarshal(body, &probe) == nil && probe.Log != nil && len(probe.Log.Entries) > 0 {
			spec, err = apispec.ParseHAR(body)
		} else {
			spec, err = apispec.ParseOpenAPI(body)
		}
	}
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	spec.Dedup()
	writeJSON(w, 200, map[string]any{
		"source":    spec.Source,
		"version":   spec.Version,
		"title":     spec.Title,
		"base_path": spec.BasePath,
		"endpoints": spec.Endpoints(),
		"types":     spec.Types(),
		"refs":      spec.Refs(),
		"count":     spec.Len(),
	})
}

// hAPISpecGraphQL 对一个 GraphQL 端点做 1 次只读 introspection（POST 固定 query），
// 返回类型名清单。目标需通过 SSRF 校验与 allow_hosts 白名单。
func (s *Server) hAPISpecGraphQL(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgSnap() // A-09：读配置快照（一次请求/操作内一致）
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	raw := strings.TrimSpace(body.Endpoint)
	if raw == "" {
		writeJSON(w, 400, map[string]any{"error": "endpoint 不能为空"})
		return
	}
	_, host, _, err := target.Validate(raw, cfg.Scan.Resolve)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if !target.Allowed(host, cfg.Scan.AllowHosts) {
		writeJSON(w, 400, map[string]any{"error": "目标不在 allow_hosts 授权白名单：" + host})
		return
	}
	// V-07：传输层交给 httpx（禁跟随重定向 + 拨号层一次解析/校验/按 IP 拨号），
	// Resolve 跟随 scan.resolve 姿态，堵住校验与建连之间的 DNS 重绑定窗口。
	spec, err := apispec.DiscoverGraphQL(raw, apispec.DiscoverOptions{Resolve: cfg.Scan.Resolve})
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"source": spec.Source, "endpoint": raw,
		"types": spec.Types(), "count": spec.Len(),
	})
}
