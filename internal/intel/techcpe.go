// tech_cpe 别名消费（D5）：指纹技术名 → CPE vendor/product → NVD 字典
// 按 CPE 精确检索，出 possible 级情报行。
//
// 判定口径（诚实）：NVD 行无逐版本区间解析（CPE 边界 → 版本区间推导是
// 3.1 计划），本通道只出 possible（同名提示级），confirmed 判定仍以
// vuln_kb 精选区间为准。技术名在 CPE 表里以小写精确匹配——表本身由
// update-fp 从社区指纹库导出，键为指纹库原名。
package intel

import (
	"encoding/json"
	"os"
	"strings"
)

// AttachTechCPE 挂载技术名 → CPE 映射（nil = 不启用）。
// C-10：映射由启动期/热重载写，扫描线程 nvdPossible 读，必须走 auxMu。
func (k *KB) AttachTechCPE(m map[string]string) {
	if k == nil {
		return
	}
	k.auxMu.Lock()
	k.techCPE = m
	k.auxMu.Unlock()
}

// LoadTechCPE 从 tech_cpe.json 加载映射；文件缺失返回 (nil, nil)。
func LoadTechCPE(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var box struct {
		CPE map[string]string `json:"cpe"`
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(box.CPE))
	for name, cpe := range box.CPE {
		m[strings.ToLower(name)] = cpe
	}
	return m, nil
}

// techCPEVendorProduct 从 cpe23Uri 取 "vendor/product"（与 nvd_sync 的
// 三返回值版本不同：这里只要联合键）。
func techCPEVendorProduct(cpe string) string {
	// cpe:2.3:a:vendor:product:...
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 || parts[0] != "cpe" {
		return ""
	}
	return parts[3] + "/" + parts[4]
}

// nvdPossible 按 CPE 检索 NVD 字典出 possible 级情报行。
// 每技术上限 maxPerTech 条，严重度优先（由 NVDStore.ByProduct 的确定性
// 排序保证，C2-05）；CVE 与既有输出去重由调用方 seen 承担。
func (k *KB) nvdPossible(techName string, seen map[int64]bool, out *[]Finding, intent nvdIntent) {
	if k == nil || out == nil {
		return
	}
	// C-10：techCPE 读侧持 auxMu 快照；nvd 只走带锁访问器。
	k.auxMu.RLock()
	cpe := k.techCPE[strings.ToLower(strings.TrimSpace(techName))]
	k.auxMu.RUnlock()
	if cpe == "" {
		return
	}
	vp := techCPEVendorProduct(cpe)
	if vp == "" {
		return
	}
	var nvd *NVDStore
	if intent == intentLoad {
		nvd = k.nvdStore() // 显式以 NVD 为数据源：可按需解码
	} else {
		nvd = k.NVDIfLoaded() // 惰性口径：索引未常驻就不出 CPE 通道行
	}
	if nvd == nil {
		return
	}
	entries := nvd.ByProduct(strings.ToLower(vp), maxPerTech*2)
	n := 0
	for _, e := range entries {
		if n >= maxPerTech {
			return
		}
		// NVD 行无 ID 语义，用 CVE 哈希占位去重（负数段避开 vuln_kb 正 ID
		// 空间）。C2-05：64 位 FNV 取低 63 位，避免旧 32 位 %1e9 的静默碰撞。
		fakeID := -int64(hash64(e.CVE) & 0x7fffffffffffffff)
		if fakeID == 0 {
			fakeID = -1
		}
		if seen[fakeID] {
			continue
		}
		seen[fakeID] = true
		*out = append(*out, Finding{
			Tech: techName, Src: "nvd",
			Name: firstRunes(e.Descr, 120), Title: firstRunes(e.Descr, 120),
			Product:    vp,
			CVE:        e.CVE,
			Severity:   e.Sev,
			SeverityZh: severityZhOf(e.Sev),
			CVSSScore:  e.Score, CVSSSev: e.Sev,
			Desc:    e.Descr,
			Verdict: "possible",
			KEV:     k.IsKEV(e.CVE),
		})
		n++
	}
}

// hash64 FNV-1a 64 位（占位 ID 用，碰撞概率可忽略）。
func hash64(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
