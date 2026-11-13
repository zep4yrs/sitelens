package netx

import (
	"strings"
	"testing"
)

// TestScopeGuardDial 拨号层 ScopeGuard：allow_hosts 不含目标时零拨号拒绝。
func TestScopeGuardDial(t *testing.T) {
	cfg := Config{AllowedHosts: []string{"example.com"}}
	if _, err := Dial(Target{Scheme: "tcp", Host: "example.org", Port: 80}, cfg, false); err == nil ||
		!strings.Contains(err.Error(), "allow_hosts") {
		t.Fatalf("白名单外目标应被拒绝，实际 err=%v", err)
	}
}

// TestScopeGuardDNSQuery DNS 查询同样过 allow_hosts。
func TestScopeGuardDNSQuery(t *testing.T) {
	cfg := Config{AllowedHosts: []string{"example.com"}, TimeoutMS: 200}
	if _, err := DNSQuery(cfg, "not-example.org", "A"); err == nil ||
		!strings.Contains(err.Error(), "allow_hosts") {
		t.Fatalf("白名单外域名 DNS 查询应被拒绝，实际 err=%v", err)
	}
}
