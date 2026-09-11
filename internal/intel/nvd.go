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

// AttachNVD 旁路挂载 NVD 索引（nil = 不启用）。
func (k *KB) AttachNVD(s *NVDStore) { k.nvd = s }

// NVDCount 统计用（未挂载返回 0）。
func (k *KB) NVDCount() int {
	if k.nvd == nil {
		return 0
	}
	return k.nvd.Len()
}

// nvdFill 在 Match 构造 Finding 后补全缺失的 CVSS（宁缺毋滥：只填空位）。
func (k *KB) nvdFill(f *Finding) {
	if k.nvd == nil || f.CVE == "" || f.CVSSScore > 0 {
		return
	}
	if e, ok := k.nvd.ByCVE(f.CVE); ok && e.Score > 0 {
		f.CVSSScore = e.Score
		if f.CVSSSev == "" {
			f.CVSSSev = e.Sev
		}
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
	s := &NVDStore{
		list:   box.Cves,
		byCVE:  make(map[string]*NVDEntry, len(box.Cves)),
		byProd: make(map[string][]*NVDEntry, 4096),
	}
	for i := range s.list {
		e := &s.list[i]
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
	sort.Slice(s.list, func(i, j int) bool { return s.list[i].CVE < s.list[j].CVE })
	return s, nil
}
