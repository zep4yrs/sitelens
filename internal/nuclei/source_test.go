package nuclei

import "testing"

func TestNormalizeSource(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http/cves/2024/CVE-2024-1234.yaml", "cves"},
		{"http/exposures/configs/git-config.yaml", "exposures"},
		{"http/exposed-panels/jenkins.yaml", "exposed-panels"},
		{"http/misconfiguration/nginx.yaml", "misconfiguration"},
		{"http/default-logins/admin.yaml", "default-logins"},
		{"network/redis-detect.yaml", "network"},
		{"dns/zone-transfer.yaml", "dns"},
		{"ssl/weak-cipher.yaml", "ssl"},
		{"legacy/old-template.yaml", "legacy"},
		{"afrog/CNVD/2018/CNVD-2018-13393.yaml", "afrog"}, // update-afrog 独立镜像目录
		{"http/unknown-category/x.yaml", "unknown"},       // 二级目录非白名单 → unknown
		{"./http/cves/a.yaml", "cves"},                    // 前导 ./ 归一
		{"", "unknown"},
		{"cves.yaml", "unknown"}, // 根文件，无来源目录
	}
	for _, c := range cases {
		if got := NormalizeSource(c.in); got != c.want {
			t.Errorf("NormalizeSource(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestEntrySourceSetOnIndex(t *testing.T) {
	// Index 落 Entry 时必须带 Source（输出分列口径依赖它）。
	e := Entry{Path: "http/cves/x.yaml"}
	if got := NormalizeSource(e.Path); got != "cves" {
		t.Fatalf("cves 来源归一失败: %s", got)
	}
}
