// 模板情报行加载与合并（update-tplintel 产物）。
package intel

import (
	"compress/gzip"
	"encoding/json"
	"os"
)

// LoadTplIntel 从 tpl_intel.json.gz 加载模板情报行（文件缺失返回 (nil, nil)）。
func LoadTplIntel(path string) ([]Entry, error) {
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
		Rows []Entry `json:"rows"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		return nil, err
	}
	return box.Rows, nil
}

// AttachTplIntel 合并模板情报行进 vuln_kb 主索引（负 ID 段避开精选行的
// 正 ID 空间），并重建关键词索引。调用须在首次 Match 之前。
func (k *KB) AttachTplIntel(rows []Entry) {
	if len(rows) == 0 {
		return
	}
	if !k.decoded {
		// A5 惰性：尚未解码时先挂起，ensureDecoded 末尾按序并入
		k.pendingTpl = append(k.pendingTpl, rows...)
		return
	}
	next := int64(-1)
	for _, r := range rows {
		next--
		r.ID = next
		k.vulns = append(k.vulns, r)
	}
	k.buildIndex()
}
