package target

import (
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeTable(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantURL      string
		wantChanges  []string // 每项按“包含”断言
		wantFragment string
	}{
		{
			name:        "缺协议默认 https",
			in:          "example.com",
			wantURL:     "https://example.com",
			wantChanges: []string{"补全协议 https"},
		},
		{
			name:        "首尾空白",
			in:          "  https://example.com  ",
			wantURL:     "https://example.com",
			wantChanges: []string{"去除首尾空白"},
		},
		{
			name:        "hxxp + defang",
			in:          "hxxp://example[.]com",
			wantURL:     "http://example.com",
			wantChanges: []string{"还原 hxxp", "失陷指标"},
		},
		{
			name:        "hxxps + defang",
			in:          "hxxps[:]//example[.]com",
			wantURL:     "https://example.com",
			wantChanges: []string{"还原 hxxp", "失陷指标"},
		},
		{
			name:        "全角冒号",
			in:          "https：//example.com",
			wantURL:     "https://example.com",
			wantChanges: []string{"全角字符转半角"},
		},
		{
			name:        "全角字母域名",
			in:          "ｇｏｖ．ｃｎ",
			wantURL:     "https://gov.cn",
			wantChanges: []string{"全角字符转半角", "补全协议 https"},
		},
		{
			name:        "协议相对地址",
			in:          "//example.com",
			wantURL:     "https://example.com",
			wantChanges: []string{"补全协议 https"},
		},
		{
			name:        "反斜杠分隔符",
			in:          "http:\\\\example.com",
			wantURL:     "http://example.com",
			wantChanges: []string{"规范协议分隔符"},
		},
		{
			name:        "缺 // 分隔符",
			in:          "https:example.com",
			wantURL:     "https://example.com",
			wantChanges: []string{"补全协议分隔符"},
		},
		{
			name:        "多余斜杠",
			in:          "https:///example.com",
			wantURL:     "https://example.com",
			wantChanges: []string{"规范协议分隔符"},
		},
		{
			name:        "尖括号包裹",
			in:          "<https://example.com>",
			wantURL:     "https://example.com",
			wantChanges: []string{"去除首尾引号"},
		},
		{
			name:        "书名号包裹",
			in:          "《https://example.com》",
			wantURL:     "https://example.com",
			wantChanges: []string{"去除首尾引号"},
		},
		{
			name:        "末尾中文句号",
			in:          "https://example.com。",
			wantURL:     "https://example.com",
			wantChanges: []string{"去除末尾标点"},
		},
		{
			name:         "锚点移除",
			in:           "https://example.com/path#frag",
			wantURL:      "https://example.com/path",
			wantChanges:  []string{"移除锚点"},
			wantFragment: "frag",
		},
		{
			name:        "URL 内嵌凭据",
			in:          "https://user:pass@example.com/",
			wantURL:     "https://example.com/",
			wantChanges: []string{"移除 URL 内嵌凭据"},
		},
		{
			name:        "https 默认端口省略",
			in:          "https://example.com:443/",
			wantURL:     "https://example.com/",
			wantChanges: []string{"省略默认端口"},
		},
		{
			name:        "http 默认端口省略",
			in:          "http://example.com:80",
			wantURL:     "http://example.com",
			wantChanges: []string{"省略默认端口"},
		},
		{
			name:        "大写与末尾根点",
			in:          "https://EXAMPLE.COM./Path",
			wantURL:     "https://example.com/Path",
			wantChanges: []string{"主机名统一小写", "去除主机名末尾根点"},
		},
		{
			name:        "gov.cn 变体归一",
			in:          "GOV.CN.",
			wantURL:     "https://gov.cn",
			wantChanges: []string{"补全协议 https", "去除主机名末尾根点"},
		},
		{
			name:        "无协议带端口",
			in:          "example.com:8080",
			wantURL:     "https://example.com:8080",
			wantChanges: []string{"补全协议 https"},
		},
		{
			name:        "IPv6 保留方括号",
			in:          "https://[::1]:8080/",
			wantURL:     "https://[::1]:8080/",
			wantChanges: nil,
		},
		{
			name:        "粘贴文本提取 URL",
			in:          "见 https://example.com/path 谢谢",
			wantURL:     "https://example.com/path",
			wantChanges: []string{"从粘贴文本中提取 URL"},
		},
		{
			name:        "已规范地址零修正",
			in:          "https://example.com/path?a=1&b=2",
			wantURL:     "https://example.com/path?a=1&b=2",
			wantChanges: nil,
		},
		{
			name:        "javascript 不补协议",
			in:          "javascript:alert(1)",
			wantURL:     "javascript:alert(1)",
			wantChanges: nil,
		},
		{
			name:        "ftp 不补协议",
			in:          "ftp://example.com",
			wantURL:     "ftp://example.com",
			wantChanges: nil,
		},
		{
			name:        "路径穿越不归一",
			in:          "https://example.com/a/../b",
			wantURL:     "https://example.com/a/../b",
			wantChanges: nil,
		},
		{
			name:        "百分号编码不动",
			in:          "https://example.com/%2e%2e/",
			wantURL:     "https://example.com/%2e%2e/",
			wantChanges: nil,
		},
		{
			name:        "空输入",
			in:          "",
			wantURL:     "",
			wantChanges: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Normalize(tc.in)
			if got.URL != tc.wantURL {
				t.Fatalf("URL = %q, want %q (changes=%v)", got.URL, tc.wantURL, got.Changes)
			}
			joined := strings.Join(got.Changes, "｜")
			for _, want := range tc.wantChanges {
				if !strings.Contains(joined, want) {
					t.Fatalf("changes = %v, 缺少 %q", got.Changes, want)
				}
			}
			if tc.wantChanges == nil && len(got.Changes) != 0 {
				t.Fatalf("不应有修正，得到 %v", got.Changes)
			}
			if got.Fragment != tc.wantFragment {
				t.Fatalf("Fragment = %q, want %q", got.Fragment, tc.wantFragment)
			}
			// 幂等：对归一化结果再跑一次，不应再产生修正。
			if tc.wantURL != "" {
				again := Normalize(tc.wantURL)
				if again.URL != tc.wantURL || len(again.Changes) != 0 {
					t.Fatalf("非幂等：Normalize(%q) = %q / %v", tc.wantURL, again.URL, again.Changes)
				}
			}
		})
	}
}

// TestNormalizeNeverChangesHost 归一化不得把目标改到另一个 host
// （只允许大小写/末尾根点这类等价变化）。
func TestNormalizeNeverChangesHost(t *testing.T) {
	inputs := []struct{ in, wantHost string }{
		{"example.com", "example.com"},
		{"hxxp://example[.]com", "example.com"},
		{"https：//EXAMPLE.COM。/path", "example.com"},
		{"//example.com", "example.com"},
		{"https://user:pass@example.com/", "example.com"},
		{"example.com:8080", "example.com"},
	}
	for _, tc := range inputs {
		got := Normalize(tc.in)
		u, err := url.Parse(got.URL)
		if err != nil {
			t.Fatalf("%q → %q 解析失败: %v", tc.in, got.URL, err)
		}
		if u.Hostname() != tc.wantHost {
			t.Fatalf("%q → host %q, want %q", tc.in, u.Hostname(), tc.wantHost)
		}
	}
}
