// 模板情报层落库（tpl_intel）：模板池 CVE 元数据 × NVD 字典 → 精选漏洞
// 情报行旁路文件（data/tpl_intel.json.gz，公开数据可再生）。
//
// 行语义：src="tpl"，product 取 NVD CPE 首个 vendor/product（无产品归属的
// 行直接丢弃——product 为空的行进不了关键词索引，纯死重）；severity 优先
// NVD 标准化值，回退模板声明值；descr 取 NVD 英文描述。verdict 恒为
// possible 级语义（区间判定仍以精选区间为准）。
package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/nuclei"
)

type tplRow struct {
	Src      string  `json:"src"`
	Name     string  `json:"name"`
	Product  string  `json:"product"`
	CVE      string  `json:"cve"`
	Type     string  `json:"type,omitempty"`
	Severity string  `json:"severity"`
	Descr    string  `json:"descr"`
	Score    float64 `json:"cvss_score,omitempty"`
}

func updateTplIntelCommand(cfg *config.Config) int {
	dir := cfg.Checks.NucleiDir
	if dir == "" {
		fmt.Fprintln(os.Stderr, "配置未启用 nuclei_dir")
		return 1
	}
	entries, err := nuclei.Index(dir, filepath.Join(cfg.Store.DataDir, "nuclei_index.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "索引构建失败：", err)
		return 1
	}
	protoN := map[string]int{}
	for _, e := range entries {
		if e.Proto != "" {
			protoN[e.Proto]++
		}
	}
	cveTplN := 0
	for _, e := range entries {
		if len(e.CVEs) > 0 {
			cveTplN++
		}
	}
	fmt.Fprintf(os.Stderr, "索引：%d 条（协议模板 tcp/dns/ssl %v；带 CVE 模板 %d）\n",
		len(entries), protoN, cveTplN)

	nvd, err := intel.LoadNVD(cfg.Intel.NVDPath)
	if err != nil || nvd == nil {
		fmt.Fprintln(os.Stderr, "NVD 字典缺失（先跑 update-nvd）：", err)
		return 1
	}

	var rows []tplRow
	seen := map[string]bool{}
	for _, e := range entries {
		for _, cve := range e.CVEs {
			ne, ok := nvd.ByCVE(cve)
			if !ok || len(ne.Prods) == 0 || ne.Prods[0].VP == "" {
				continue // 无产品归属：丢弃
			}
			key := cve + "|" + ne.Prods[0].VP
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := ne.Sev
			if sev == "" {
				sev = e.Sev
			}
			rows = append(rows, tplRow{
				Src: "tpl", Name: e.Name, Product: ne.Prods[0].VP,
				CVE: cve, Severity: sev, Descr: ne.Descr, Score: ne.Score,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Product != rows[j].Product {
			return rows[i].Product < rows[j].Product
		}
		return rows[i].CVE < rows[j].CVE
	})

	out := cfg.Intel.TplIntelPath
	if out == "" {
		out = "data/tpl_intel.json.gz"
	}
	if err := writeGzJSON(out, map[string]any{
		"version": 1,
		"count":   len(rows), "rows": rows,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "写盘失败：", err)
		return 1
	}
	// 产品维度统计
	prods := map[string]int{}
	for _, r := range rows {
		prods[r.Product]++
	}
	fmt.Fprintf(os.Stderr, "模板情报行：%d 条（覆盖 %d 个产品）→ %s\n",
		len(rows), len(prods), out)
	return 0
}

func writeGzJSON(path string, v any) error {
	f, err := os.Create(path+".tmp")
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(v); err != nil {
		f.Close()
		os.Remove(path + ".tmp")
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		os.Remove(path + ".tmp")
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path + ".tmp")
		return err
	}
	return os.Rename(path+".tmp", path)
}
