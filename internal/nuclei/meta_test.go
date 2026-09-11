package nuclei

import "testing"

func TestConvertMetaCVEs(t *testing.T) {
	yaml := `id: cve-2024-1234-example
info:
  name: Example App RCE
  severity: critical
  classification:
    cve-id: CVE-2024-1234
    cwe-id: CWE-77
  tags: rce,example
`
	name, sev, tags, cves := convertMeta(yaml)
	if name != "Example App RCE" || sev != "critical" {
		t.Errorf("基础元数据解析不对: %s %s", name, sev)
	}
	if len(tags) != 2 || tags[0] != "rce" {
		t.Errorf("tags 解析不对: %v", tags)
	}
	if len(cves) != 1 || cves[0] != "CVE-2024-1234" {
		t.Errorf("CVE 抽取不对: %v", cves)
	}

	// 多 CVE 去重 + 大小写归一
	multi := "x CVE-2023-1234 y CVE-2023-2345 z CVE-2023-1234 cve-2023-3456"
	_, _, _, cves = convertMeta(multi)
	if len(cves) != 3 {
		t.Errorf("多 CVE 去重失败: %v", cves)
	}

	// 无 CVE
	_, _, _, cves = convertMeta("info:\n  name: plain\n")
	if cves != nil {
		t.Errorf("无 CVE 应为空: %v", cves)
	}
}
