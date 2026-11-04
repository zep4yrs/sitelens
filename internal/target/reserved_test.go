package target

import (
	"net/netip"
	"testing"
)

// TestValidateIPReservedAndSpecialRanges V-19：NAT64 / 6to4 / 保留段/组播
// 一律拒绝；公网地址照常放行。
func TestValidateIPReservedAndSpecialRanges(t *testing.T) {
	old := AllowPrivate()
	SetAllowPrivate(false) // 默认姿态：私网/保留地址全拦
	defer SetAllowPrivate(old)

	blocked := []string{
		"64:ff9b::7f00:1", // NAT64 → 127.0.0.1（本轮修复的核心缺口）
		"64:ff9b::a00:1",  // NAT64 → 10.0.0.1
		"2002:7f00:1::1",  // 6to4 内嵌 127.0.0.1
		"198.18.0.1",      // benchmark
		"198.19.255.254",
		"192.0.0.8",
		"192.0.2.10",   // TEST-NET-1
		"198.51.100.7", // TEST-NET-2
		"203.0.113.9",  // TEST-NET-3
		"fec0::1",      // 站点本地（已废弃）
		"::ffff:127.0.0.1",
		"127.0.0.1",
		"10.1.2.3",
		"169.254.169.254",
		"224.0.0.1", // 组播
	}
	for _, s := range blocked {
		addr := netip.MustParseAddr(s)
		if err := ValidateIP(addr); err == nil {
			t.Errorf("ValidateIP(%s) 应被拒绝", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if err := ValidateIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("ValidateIP(%s) 应放行: %v", s, err)
		}
	}
}
