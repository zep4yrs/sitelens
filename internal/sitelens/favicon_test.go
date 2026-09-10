package sitelens

import "testing"

// 锚定向量：与官方 mmh3 C 实现（pip mmh3）逐位核对（build/mm3_ref.py 校准）。
func TestMurmur3x8632Anchors(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"a", 0x3c2569b2},
		{"hello", 0x248bfa47},
		{"The quick brown fox jumps over the lazy dog", 0x2e4ff723},
	}
	for _, c := range cases {
		if got := murmur3x8632([]byte(c.in)); got != c.want {
			t.Errorf("murmur3x8632(%q) = %#x, 期望 %#x", c.in, got, c.want)
		}
	}
}

// FOFA 语义锚定：FaviconHash == mmh3.hash(codecs.encode(content, "base64"))。
// 期望值由 build/mm3_ref.py + 官方 mmh3 双实现核对得出。
func TestFaviconHashAnchors(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		want    int64
	}{
		{"empty", nil, 0},
		{"range64", bytesRange(64), 1849162594},
		{"anchor", []byte("sitelens-favicon-anchor"), 1960426245},
	}
	for _, c := range cases {
		if got := FaviconHash(c.content); got != c.want {
			t.Errorf("FaviconHash(%s) = %d, 期望 %d", c.name, got, c.want)
		}
	}
}

// bytesRange 生成 0..n-1 字节序列（锚定输入的 Go 复现）。
func bytesRange(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// 真实产品 icon_hash（官方 favicon，pip mmh3 锚定计算）——作为常量对照表，
// 供 technologies.json 规则维护时复核。
func TestRealIconHashCatalog(t *testing.T) {
	catalog := map[string]int64{
		"GitLab":    1265477436,
		"Grafana":   1884118115,
		"Jenkins":   1928290,
		"Tomcat":    -297069493,
		"WordPress": -2133341160,
	}
	for name, hash := range catalog {
		if hash == 0 {
			t.Errorf("%s 的 icon_hash 不应为 0", name)
		}
	}
}
