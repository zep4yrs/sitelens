package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OsvClient OSV.dev 公开 API 客户端（/v1/vulns/{id}，无需凭据）。
type OsvClient struct {
	HTTP    *http.Client
	BaseURL string // 默认 https://api.osv.dev/v1
}

// NewOsvClient 默认客户端（30s 超时）。
func NewOsvClient() *OsvClient {
	return &OsvClient{HTTP: &http.Client{Timeout: 30 * time.Second}, BaseURL: "https://api.osv.dev/v1"}
}

// FetchVuln 拉取单个 CVE 的 OSV 记录。
// 404 返回（nil, nil）——该 CVE 在 OSV 无记录属正常。
func (c *OsvClient) FetchVuln(cve string) (*OsvVuln, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/vulns/" + cve)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("OSV HTTP %d", resp.StatusCode)
	}
	var v OsvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
