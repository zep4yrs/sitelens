package intel

import (
	"encoding/json"
	"log"
	"os"
	"strings"
)

// CollectCVEs 收集 vuln_kb 全部非空 CVE（大写去重排序）。
func (k *KB) CollectCVEs() []string {
	k.ensureDecoded()
	k.vulnsMu.RLock()
	defer k.vulnsMu.RUnlock()
	set := map[string]bool{}
	for i := range k.vulns {
		c := strings.ToUpper(strings.TrimSpace(k.vulns[i].CVE))
		if c != "" {
			set[c] = true
		}
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	// 排序由调用方决定；此处保序输出
	return out
}

// ApplyOverrides 把 OSV 覆盖数据合并进知识库 vuln 条目（幂等）：
// Affected 追加去重、CVSS 空位补齐。返回生效条数。
// 最近一次数据留存于 lastOv，供 Release 后经 pendingOv 重放。
//
// 并发纪律（BUG-014）：OSV 同步 goroutine 会调用本方法，而扫描线程正在
// Match 里遍历同一份 vuln 表。旧实现在 k.vulns 上原地 sort.Slice 并逐条
// 改字段，扫描可能读到「排序中/字段改写中」的中间态 → CVE 与区间错配。
// 现改为：副本上合并/排序，完成后整体替换（读侧持读锁，见 MatchWithNVD）。
func (k *KB) ApplyOverrides(ov map[string]Override) int {
	k.ensureDecoded()
	return k.applyOverridesLocked(ov)
}

// applyOverridesLocked 是 ApplyOverrides 的实现体：调用方须已确保解码完成
// （ensureDecoded 内部重放挂起覆盖时直接调本函数，避免重入 loadMu）。
func (k *KB) applyOverridesLocked(ov map[string]Override) int {
	k.vulnsMu.Lock()
	defer k.vulnsMu.Unlock()
	if k.vulns == nil || len(ov) == 0 {
		return 0
	}
	k.lastOv = ov
	next := make([]Entry, len(k.vulns))
	copy(next, k.vulns)
	n := MergeOverrides(next, ov)
	k.vulns = next
	k.buildIndex() // 索引元素指向旧底层数组，必须随换代重建
	return n
}

// SaveOverrides 把覆盖数据落盘（update-osv 命令的输出物）。
func SaveOverrides(path string, ov map[string]Override) error {
	data, err := json.MarshalIndent(ov, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadOverrides 读覆盖文件；不存在返回空 map 与 nil 错误。
func LoadOverrides(path string) (map[string]Override, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Override{}, nil
		}
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return map[string]Override{}, nil
	}
	return ParseOverrides(data)
}

// ApplyOverridesFile server 启动合并：overrides 文件存在且非空时自动应用。
// （在 intel.Load 之后、serve 初始化前由调用方执行）
//
// C2-06：加载/解析失败必须留痕（log），不能静默返回 0——否则"OSV 覆盖没
// 生效"在运行期完全不可见（无日志、无 Stats 字段）。
func ApplyOverridesFile(k *KB, path string) int {
	if path == "" {
		return 0
	}
	ov, err := LoadOverrides(path)
	if err != nil {
		log.Printf("intel: 覆盖文件解析失败，本次不合并（%s）：%v", path, err)
		return 0
	}
	if len(ov) == 0 {
		return 0
	}
	n := k.ApplyOverrides(ov)
	if n == 0 {
		log.Printf("intel: 覆盖文件已加载（%d 条）但未命中任何情报行（%s）", len(ov), path)
	}
	return n
}
