// A6 模板编译缓存（4.0 Track A）：nuclei.LoadFile 每次都读文件并重编译，
// full 档单次可选几百个模板、apocalypse 全量轮换上万条——同一模板被反复
// 扫描时编译成本（读盘 + YAML 解析 + 转换 + 正则编译）被重复支付。
//
// 本文件在 LoadFile 之上加一层进程级缓存，键 = 模板路径 + 文件 mtime + 大小：
// 模板文件一旦更新（update-nuclei），键变化自然失效，不存在陈旧缓存问题。
//
// 容量上限：超限淘汰最旧（简单计数轮转，避免引入第三方 LRU）。
// 缓存的 []checks.Check 在使用方被视为只读（Check 编译后不可变）。
package nuclei

import (
	"os"
	"sync"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
)

type cacheKey struct {
	path  string
	mtime int64
	size  int64
}

type cacheEntry struct {
	checks []checks.Check
	seq    uint64 // 插入序号（淘汰用）
}

var (
	tplMu       sync.Mutex
	tplCache    = map[cacheKey]cacheEntry{}
	tplCacheMax = 4096
	tplCacheSeq uint64 // 淘汰计数器：每个键带序号，超限删最小序号
)

// loadFileCached 带缓存的 LoadFile。命中则零拷贝返回缓存切片（只读约定）。
func loadFileCached(path string) ([]checks.Check, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	key := cacheKey{path: path, mtime: st.ModTime().UnixNano(), size: st.Size()}

	tplMu.Lock()
	if e, ok := tplCache[key]; ok {
		tplMu.Unlock()
		return e.checks, nil
	}
	tplMu.Unlock()

	cs, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return cs, nil // 空转换结果不缓存（可能是临时损坏的模板）
	}

	tplMu.Lock()
	if len(tplCache) >= tplCacheMax {
		evictOldest()
	}
	tplCacheSeq++
	tplCache[key] = cacheEntry{checks: cs, seq: tplCacheSeq}
	tplMu.Unlock()
	return cs, nil
}

// evictOldest 淘汰序号最小的键（调用方须持 tplMu）。
func evictOldest() {
	var oldest cacheKey
	var minSeq uint64
	first := true
	for k, e := range tplCache {
		if first || e.seq < minSeq {
			oldest, minSeq, first = k, e.seq, false
		}
	}
	if !first {
		delete(tplCache, oldest)
	}
}

// LoadFileCached LoadFile 的带缓存版本（A6）。导出供引擎使用。
func LoadFileCached(path string) ([]checks.Check, error) {
	return loadFileCached(path)
}
