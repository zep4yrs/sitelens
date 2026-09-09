package intel

import (
	"encoding/json"
	"os"
	"strings"
)

// CollectCVEs 收集 vuln_kb 全部非空 CVE（大写去重排序）。
func (k *KB) CollectCVEs() []string {
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
func (k *KB) ApplyOverrides(ov map[string]Override) int {
	if k.vulns == nil {
		return 0
	}
	return MergeOverrides(k.vulns, ov)
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

// server 启动合并：overrides 文件存在且非空时自动应用。
// （在 intel.Load 之后、serve 初始化前由调用方执行）
func ApplyOverridesFile(k *KB, path string) int {
	if path == "" {
		return 0
	}
	ov, err := LoadOverrides(path)
	if err != nil || len(ov) == 0 {
		return 0
	}
	return k.ApplyOverrides(ov)
}
