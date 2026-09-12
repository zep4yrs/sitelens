// Package beacon 自托管出带回调注册表：SSRF 探测把 beacon 地址塞进
// 目标参数，目标侧回连本服务 /b/<token> 即记录命中——纯进程内共享，
// serve 与引擎同二进制，无需 HTTP 自查询。
//
// B5 防污染：只登记「已预订」的 token（探测方生成后先 Reserve 报备），
// 未预订 token 的回连一律 404 忽略——任意客户端无法凭空污染注册表，
// 也就无法伪造其他扫描的命中。
//
// 复扫 B4 收口：预订表有界（FIFO 淘汰）、回连记录带 TTL、Reset 连
// 预订表一并清空——长驻 serve 不再单调增长，已 Reset 的旧 token
// 不能复活命中。
package beacon

import (
	"sync"
	"time"
)

const (
	maxEntries = 512              // 回连记录上限（超出淘汰最旧）
	maxIssued  = 65536            // 预订表上限（历史累计出带次数级别，扫描量远低于此）
	hitTTL     = 30 * time.Minute // 回连记录时效：过期即失效，杜绝幽灵命中
)

var (
	mu          sync.Mutex
	hits        = map[string]time.Time{}
	order       []string
	issued      = map[string]bool{}
	issuedOrder []string
)

// Reserve 预订一个 token（探测方生成后先报备，回连才会被记录）。
// 预订表超上限时按 FIFO 淘汰最旧预订——正常扫描单轮预订量数十级，
// 65536 上限只约束长驻进程的累计增长。
func Reserve(token string) {
	if token == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if !issued[token] {
		if len(issuedOrder) >= maxIssued {
			delete(issued, issuedOrder[0])
			issuedOrder = issuedOrder[1:]
		}
		issuedOrder = append(issuedOrder, token)
	}
	issued[token] = true
}

// Hit 记录一次回连（token 即路径随机段）。未预订的 token 忽略；
// 过期记录顺带清理。
func Hit(token string) {
	if token == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	pruneHits()
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

// Hits 返回已回连的 token 列表（时间序，先剔除过期条目）。
func Hits() []string {
	mu.Lock()
	defer mu.Unlock()
	pruneHits()
	out := make([]string, 0, len(order))
	out = append(out, order...)
	return out
}

// Reset 清空全部状态（新扫描开始前或显式重置时调用）。
// 预订表一并清理：Reset 之后的旧 token 不重新 Reserve 不能再命中。
func Reset() {
	mu.Lock()
	hits = map[string]time.Time{}
	order = nil
	issued = map[string]bool{}
	issuedOrder = nil
	mu.Unlock()
}

// pruneHits 剔除超过 TTL 的回连记录；order 按时间序追加，从头部裁剪即可。
// 须持锁调用。
func pruneHits() {
	now := time.Now()
	cut := 0
	for cut < len(order) && now.Sub(hits[order[cut]]) > hitTTL {
		delete(hits, order[cut])
		cut++
	}
	if cut > 0 {
		order = order[cut:]
	}
}
