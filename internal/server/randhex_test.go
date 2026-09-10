package server

import (
	"regexp"
	"testing"
)

// TestRandHex randHex 行为验证：长度正确、字符集为十六进制、多次调用
// 不相同（crypto/rand 熵）。回归背景：审计 STD-2（原实现时间派生熵低
// 且名不符实）。
func TestRandHex(t *testing.T) {
	hexRe := regexp.MustCompile("^[0-9a-f]+$")
	seen := map[string]bool{}
	for _, n := range []int{1, 4, 8, 32} {
		got := randHex(n)
		if len(got) != n {
			t.Fatalf("randHex(%d) 长度错误: %d", n, len(got))
		}
		if !hexRe.MatchString(got) {
			t.Fatalf("randHex(%d) 含非十六进制字符: %q", n, got)
		}
		seen[got] = true
	}
	if len(seen) < 3 {
		t.Fatalf("多次调用应产生不同值: %v", seen)
	}
}

// TestNewIDFormat newID 总长与格式（8 位时间前缀 + 8 位随机后缀）。
func TestNewIDFormat(t *testing.T) {
	id := newID()
	if len(id) != 12 {
		t.Fatalf("newID 长度应为 12: %q", id)
	}
	hexRe := regexp.MustCompile("^[0-9a-f]{12}$")
	if !hexRe.MatchString(id) {
		t.Fatalf("newID 应为十六进制: %q", id)
	}
}
