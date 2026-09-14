package intel

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// NVD 全量 CVE 索引（data/nvd_cves.json.gz，公开数据，update-nvd 可再生）。
//
// 定位是「CVE 字典 + 评分兜底」：vuln_kb 依然是三级判定主库，NVD 侧提供
// ① vuln_kb 行缺 CVSS 时的评分补全；② 按 CVE/厂商产品的检索面。
// 文件缺失时 AttachNVD 跳过，情报层其余功能不受影响。

// NVDProd 一条 CPE 受影响产品约束（vendor/product + 可选版本边界）。
type NVDProd struct {
	VP string `json:"vp"`           // vendor/product
	EE string `json:"ee,omitempty"` // versionEndExcluding
	EI string `json:"ei,omitempty"` // versionEndIncluding
	SE string `json:"se,omitempty"` // versionStartExcluding
	SI string `json:"si,omitempty"` // versionStartIncluding
	V  string `json:"v,omitempty"`  // 单版本（无边界时）
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
	// CWEs 弱类型编号（CWE-NNN，去重升序）。4.0 P5 新增：来自 NVD 的
	// weaknesses 字段（NVD-CWE-* / NVD-CWE-noinfo 等占位值被过滤）。
	// 旧数据文件（未含该字段）加载后为 nil，消费方按空处理——向后兼容。
	CWEs []string `json:"cwes,omitempty"`
}

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
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// AttachNVD 直接挂载已解码的 NVD 索引（nil = 不启用）。
// 已持有索引的调用方用这个；只有路径的调用方用 AttachNVDPath（惰性）。
func (k *KB) AttachNVD(s *NVDStore) { k.nvd = s }

// AttachNVDPath 惰性挂载 NVD：**只记路径**，首次真正用到时才解码索引（A3）。
//
// 动机：NVD 全量索引（30 万+ CVE）实测占 HeapSys ≈1.7GB，而指纹/端口类扫描
// 根本用不到它——此前每次启动都全量解码，是引擎空闲 RSS ≈1GB 的主因。
// 本方法让「用不到就不加载」；真需要时（CVSS 补全 / CPE 检索）自动解码一次。
func (k *KB) AttachNVDPath(path string) {
	if k == nil || path == "" {
		return
	}
	k.nvdPath = path
}

// HasNVD 报告是否配置了 NVD 数据源（**不触发加载**）。
// 供「是否做 CVE→CWE 关联」这类判断使用，避免判断本身把索引拉起来。
func (k *KB) HasNVD() bool {
	if k == nil {
		return false
	}
	return k.nvd != nil || k.nvdPath != ""
}

// nvdStore 取 NVD 索引；未挂载时按需惰性加载（线程安全，只加载一次）。
// 所有内部读取都应经此函数；对外用 NVD()。
func (k *KB) nvdStore() *NVDStore {
	if k == nil {
		return nil
	}
	if k.nvd != nil {
		return k.nvd
	}
	if k.nvdPath == "" {
		return nil
	}
	k.nvdOnce.Do(func() {
		s, err := LoadNVD(k.nvdPath)
		if err != nil {
			k.nvdErr = err
			return
		}
		k.nvd = s
	})
	return k.nvd
}

// NVD 返回 NVD 索引（未挂载/加载失败返回 nil）。**会触发惰性加载**——
// 供 cwe.Relate 等确实需要数据的消费方使用；只做存在性判断请用 HasNVD。
func (k *KB) NVD() *NVDStore { return k.nvdStore() }

// NVDCount 统计用：已解码的条数（**不触发加载**，避免统计动作拉起 1.7GB）。
func (k *KB) NVDCount() int {
	if k == nil || k.nvd == nil {
		return 0
	}
	return k.nvd.Len()
}

// nvdFill 在 Match 构造 Finding 后补全缺失的 CVSS 与 CWE（宁缺毋滥：只填空位）。
func (k *KB) nvdFill(f *Finding) {
	if f.CVE == "" {
		return
	}
	nvd := k.nvdStore() // A3：真正需要 CVSS/CWE 时才加载
	if nvd == nil {
		return
	}
	e, ok := nvd.ByCVE(f.CVE)
	if !ok {
		return
	}
	if f.CVSSScore <= 0 && e.Score > 0 {
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
