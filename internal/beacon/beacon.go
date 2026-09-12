// Package beacon 自托管出带回调注册表：SSRF 探测把 beacon 地址塞进
// 目标参数，目标侧回连本服务 /b/<token> 即记录命中——纯进程内共享，
// serve 与引擎同二进制，无需 HTTP 自查询。
//
// B5 防污染：只登记「已预订」的 token（探测方生成后先 Reserve 报备），
// 未预订 token 的回连一律 404 忽略——任意客户端无法凭空污染注册表，
// 也就无法伪造其他扫描的命中。
package beacon

import (
	"sync"
	"time"
)

const maxEntries = 512

var (
	mu     sync.Mutex
	hits   = map[string]time.Time{}
	order  []string
	issued = map[string]bool{}
)

// Reserve 预订一个 token（探测方生成后先报备，回连才会被记录）。
func Reserve(token string) {
	if token == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	issued[token] = true
}

// Hit 记录一次回连（token 即路径随机段）。未预订的 token 忽略。
func Hit(token string) {
	if token == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if !issued[token] {
		return
	}
	if _, dup := hits[token]; !dup && len(order) >= maxEntries {
		// 淘汰最旧
		delete(hits, order[0])
		order = order[1:]
	}
	if _, dup := hits[token]; !dup {
		order = append(order, token)
	}
	hits[token] = time.Now()
}

// Hits 返回已回连的 token 列表（时间序）。
func Hits() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(order))
	out = append(out, order...)
	return out
}

// Reset 清空（新扫描开始前调用，防跨扫描串扰）。
func Reset() {
	mu.Lock()
	hits = map[string]time.Time{}
	order = nil
	mu.Unlock()
}
