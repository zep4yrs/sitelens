package intel

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"os"
	"sort"
	"strings"
)

// NVD 全量 CVE 索引（data/nvd_cves.json.gz，公开数据，update-nvd 可再生）。
//
// 定位是「CVE 字典 + 评分兜底」：vuln_kb 依然是三级判定主库，NVD 侧提供
// ① vuln_kb 行缺 CVSS 时的评分补全；② 按 CVE/厂商产品的检索面。
// 文件缺失时 AttachNVD 跳过，情报层其余功能不受影响。

// NVDProd 一条 CPE 受影响产品约束。
//
// A2 字段瘦身（4.0 Track A）：常驻结构**只保留 vendor/product**。
// 原结构含 6 个 string 字段（96B/条 × 约 300 万条 ≈ 292MB），但全仓核实
// **版本边界字段（EE/EI/SE/SI/V）无任何消费方**——版本区间判定由
// vuln_kb / affected_ranges 承担，NVD 侧只做「产品名 → CVE」检索。
// 瘦到 16B/条后该项内存降约 240MB（full 档峰值主因之一）。
//
// 取舍：新版 update-nvd 写出的文件不再含版本边界字段。该字段可从 NVD 源
// 随时重建（`update-nvd feed`，实测约 5 分钟），故属可恢复的数据精简。
// 旧文件（含边界）用新结构解码**完全兼容**（未知字段被忽略）。
type NVDProd struct {
	VP string `json:"vp"` // vendor/product
}

// NVDEntry 一条 CVE 的紧凑投影。
type NVDEntry struct {
	CVE    string    `json:"cve"`
	Pub    string    `json:"pub,omitempty"`
	Mod    string    `json:"mod,omitempty"`
	Sev    string    `json:"sev,omitempty"`   // base severity（小写）
	Score  float64   `json:"score,omitempty"` // CVSS base score
	Vector string    `json:"vec,omitempty"`   // CVSS vector string
	Descr  string    `json:"descr,omitempty"` // 英文首条描述（截断）
	Prods  []NVDProd `json:"prods,omitempty"` // 受影响产品约束（去重）
	// ScoreSet 标记 Score 是否来自真实评分数据（含合法的 0.0）。C2-04：
	// CVSS 3.1 规范允许基础分 0.0（Impact<=0 时基础分即 0），旧实现用
	// Score==0 当"缺失"哨兵，会把 0 分 CVE 当成无评分交给 ML 兜底
	// （sev-linear 在描述文本上通常给 5~9 分）。写端取到 metric 即置 true；
	// 读端用 HasScore() 兼容旧文件（无该字段 → 回退 Score>0）。
	ScoreSet bool `json:"score_set,omitempty"`
	// CWEs 弱类型编号（CWE-NNN，去重升序）。4.0 P5 新增：来自 NVD 的
	// weaknesses 字段（NVD-CWE-* / NVD-CWE-noinfo 等占位值被过滤）。
	// 旧数据文件（未含该字段）加载后为 nil，消费方按空处理——向后兼容。
	CWEs []string `json:"cwes,omitempty"`
}

// HasScore 报告该条是否携带真实 CVSS 评分（0.0 也算真实评分）。
// 旧数据文件没有 score_set 字段：回退到 Score>0 的兼容判定。
func (e NVDEntry) HasScore() bool { return e.ScoreSet || e.Score > 0 }

// NVDStore 内存索引（不可变，可并发读）。
type NVDStore struct {
	list   []NVDEntry
	byCVE  map[string]*NVDEntry
	byProd map[string][]*NVDEntry // vendor/product → 条目
}

// Len 条目数。
func (s *NVDStore) Len() int { return len(s.list) }

// ByCVE 精确 CVE 查询。
func (s *NVDStore) ByCVE(cve string) (*NVDEntry, bool) {
	if s == nil {
		return nil, false
	}
	e, ok := s.byCVE[strings.ToUpper(strings.TrimSpace(cve))]
	return e, ok
}

// CWEsFor 返回 CVE 的 CWE 编号（去重副本；未知 CVE 或旧数据返回 nil）。
// 4.0 P5：供 cwe_rel 的 CVE↔CWE 关联使用。
func (s *NVDStore) CWEsFor(cve string) []string {
	e, ok := s.ByCVE(cve)
	if !ok || len(e.CWEs) == 0 {
		return nil
	}
	out := make([]string, len(e.CWEs))
	copy(out, e.CWEs)
	return out
}

// ByProduct 按 vendor/product 或其子串检索（q 逐条做子串匹配，小库量级够用）。
//
// C2-05：结果必须**确定**且**严重度优先**。旧实现直接按 map 迭代顺序收集，
// 同一查询每次运行（甚至同进程内）返回的子集都可能不同，调用方按 limit
// 截断时可能丢掉高分条目。这里先全量收集去重，再按
// (有评分优先, score 降序, CVE 升序) 稳定排序后截断。
func (s *NVDStore) ByProduct(q string, limit int) []NVDEntry {
	if s == nil || q == "" || limit <= 0 {
		return nil
	}
	q = strings.ToLower(q)
	var out []NVDEntry
	seen := map[*NVDEntry]bool{}
	for prod, entries := range s.byProd {
		if !strings.Contains(prod, q) {
			continue
		}
		for _, e := range entries {
			if seen[e] {
				continue
			}
			seen[e] = true
			out = append(out, *e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		hi, hj := out[i].HasScore(), out[j].HasScore()
		if hi != hj {
			return hi
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].CVE < out[j].CVE
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// AttachNVD 直接挂载已解码的 NVD 索引（nil = 不启用）。
// 已持有索引的调用方用这个；只有路径的调用方用 AttachNVDPath（惰性）。
func (k *KB) AttachNVD(s *NVDStore) {
	if k == nil {
		return
	}
	k.nvdMu.Lock()
	k.nvd = s
	k.nvdMu.Unlock()
}

// AttachNVDPath 惰性挂载 NVD：**只记路径**，首次真正用到时才解码索引（A3）。
//
// 动机：NVD 全量索引（30 万+ CVE）实测占 HeapSys ≈1.7GB，而指纹/端口类扫描
// 根本用不到它——此前每次启动都全量解码，是引擎空闲 RSS ≈1GB 的主因。
// 本方法让「用不到就不加载」；真需要时（CVSS 补全 / CPE 检索）自动解码一次。
func (k *KB) AttachNVDPath(path string) {
	if k == nil || path == "" {
		return
	}
	k.nvdMu.Lock()
	k.nvdPath = path
	k.nvdMu.Unlock()
}

// HasNVD 报告是否配置了 NVD 数据源（**不触发加载**）。
// 供「是否做 CVE→CWE 关联」这类判断使用，避免判断本身把索引拉起来。
func (k *KB) HasNVD() bool {
	if k == nil {
		return false
	}
	k.nvdMu.Lock()
	defer k.nvdMu.Unlock()
	return k.nvd != nil || k.nvdPath != ""
}

// NVDLoaded 报告 NVD 索引是否**已经**在本进程解码常驻（**不触发加载**）。
// 供收尾富化这类「索引现成才顺带查一下」的消费方使用：扫描收尾绝不能
// 首次拉起全量索引（30 万+ 条 ≈1.7GB 常驻、秒级同步阻塞），只需查询的
// 动作不该付出拉起的代价——那是确实需要数据的消费方（nvdFill 等）的事。
func (k *KB) NVDLoaded() bool {
	return k.NVDIfLoaded() != nil
}

// NVDIfLoaded 返回**已常驻**的 NVD 索引（未加载返回 nil，绝不触发加载）。
// C2-02：graph 收尾的 CWE/CVSS 富化只允许用本函数——旧代码走 NVD() 会在
// 扫描收尾隐式拉起 1.7GB 索引，与 A3 惰性纪律相反。
func (k *KB) NVDIfLoaded() *NVDStore {
	if k == nil {
		return nil
	}
	k.nvdMu.Lock()
	defer k.nvdMu.Unlock()
	return k.nvd
}

// nvdStore 取 NVD 索引；未挂载时按需惰性加载（线程安全）。
// Release 复位 nvdTried 后可再次加载；所有内部读取都应经此函数；对外用 NVD()。
func (k *KB) nvdStore() *NVDStore {
	if k == nil {
		return nil
	}
	k.nvdMu.Lock()
	defer k.nvdMu.Unlock()
	if k.nvd != nil {
		return k.nvd
	}
	if k.nvdPath == "" {
		return nil
	}
	if k.nvdTried { // 已尝试过（成功或失败），维持现值
		return k.nvd
	}
	k.nvdTried = true
	s, err := LoadNVD(k.nvdPath)
	if err != nil {
		k.nvdErr = err
		log.Printf("intel: NVD 索引加载失败（%s）：%v", k.nvdPath, err)
		return nil
	}
	k.nvd = s
	return s
}

// NVD 返回 NVD 索引（未挂载/加载失败返回 nil）。**会触发惰性加载**——
// 供 cwe.Relate 等确实需要数据的消费方使用；只做存在性判断请用 HasNVD，
// 扫描收尾/图收尾等"顺带查询"场景请用 NVDIfLoaded。
func (k *KB) NVD() *NVDStore { return k.nvdStore() }

// NVDCount 统计用：已解码的条数（**不触发加载**，避免统计动作拉起 1.7GB）。
func (k *KB) NVDCount() int {
	s := k.NVDIfLoaded()
	if s == nil {
		return 0
	}
	return s.Len()
}

// nvdFill 在 Match 构造 Finding 后补全缺失的 CVSS 与 CWE（宁缺毋滥：只填空位）。
//
// intentLoad 才允许首次拉起索引（见 nvdIntent）；intentLazy 下索引未常驻直接
// 返回——扫描收尾的富化不得为「补个字段」付出秒级同步解码 + 1.7GB 常驻。
func (k *KB) nvdFill(f *Finding, intent nvdIntent) {
	if f.CVE == "" {
		return
	}
	var nvd *NVDStore
	if intent == intentLoad {
		nvd = k.nvdStore() // 显式以 NVD 为数据源：可按需解码
	} else {
		nvd = k.NVDIfLoaded() // 惰性口径：只用已常驻索引，不触发加载
	}
	if nvd == nil {
		return
	}
	e, ok := nvd.ByCVE(f.CVE)
	if !ok {
		return
	}
	// C2-04：用 HasScore 判"有没有评分"，0.0 也是合法评分——否则 0 分
	// CVE 会被当成缺字段，后续被 ML 严重度兜底改写。
	if f.CVSSScore <= 0 && e.HasScore() {
		f.CVSSScore = e.Score
		if f.CVSSSev == "" {
			f.CVSSSev = e.Sev
		}
	}
	// CWE 回填（P5）：来自 NVD weaknesses；已有值不覆盖。
	if len(f.CWEs) == 0 && len(e.CWEs) > 0 {
		out := make([]string, len(e.CWEs))
		copy(out, e.CWEs)
		f.CWEs = out
	}
}

// LoadNVD 从 nvd_cves.json.gz 加载索引；文件缺失返回 (nil, nil)。
func LoadNVD(path string) (*NVDStore, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var box struct {
		Cves []NVDEntry `json:"cves"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		return nil, err
	}
	// 先排序、再建索引：byCVE/byProd 存的是 *NVDEntry 指针，若在排序前建立，
	// sort 移动元素会使指针悬空指向错位条目（真实 bug：feed 按年份拼接的文件
	// 非全局有序，会触发此问题，表现为查到他人 CWE/CVSS）。
	sort.Slice(box.Cves, func(i, j int) bool { return box.Cves[i].CVE < box.Cves[j].CVE })

	s := &NVDStore{
		list:   box.Cves,
		byCVE:  make(map[string]*NVDEntry, len(box.Cves)),
		byProd: make(map[string][]*NVDEntry, 4096),
	}
	for i := range s.list {
		e := &s.list[i] // 排序已定，指针稳定
		s.byCVE[strings.ToUpper(e.CVE)] = e
		seen := map[string]bool{}
		for _, p := range e.Prods {
			if seen[p.VP] {
				continue
			}
			seen[p.VP] = true
			s.byProd[strings.ToLower(p.VP)] = append(s.byProd[strings.ToLower(p.VP)], e)
		}
	}
	return s, nil
}
