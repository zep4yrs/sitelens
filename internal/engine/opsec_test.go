package engine

import (
	"testing"
	"time"
)

func TestOpsecRatePresets(t *testing.T) {
	cases := []struct {
		opsec    string
		inIval   time.Duration
		inRPS    int
		wantIval time.Duration
		wantRPS  int
		wantAdap bool
	}{
		{"stealth", 0, 0, 1200 * time.Millisecond, 2, false},
		{"stealth", 400 * time.Millisecond, 8, 1200 * time.Millisecond, 2, false},
		{"evasive", 0, 0, 800 * time.Millisecond, 4, false},
		{"evasive", 100 * time.Millisecond, 8, 800 * time.Millisecond, 4, false},
		{"balanced", 400 * time.Millisecond, 8, 400 * time.Millisecond, 8, true},
		{"noisy", 0, 0, 200 * time.Millisecond, 8, false},
		{"noisy", 500 * time.Millisecond, 3, 200 * time.Millisecond, 3, false}, // 更保守的显式上限优先
		{"", 400 * time.Millisecond, 8, 400 * time.Millisecond, 8, true},
		{"unknown", 400 * time.Millisecond, 8, 400 * time.Millisecond, 8, true},
	}
	for _, c := range cases {
		ival, rps, adap := opsecRate(c.opsec, c.inIval, c.inRPS, c.opsec == "" || c.opsec == "balanced" || c.opsec == "unknown")
		if ival != c.wantIval || rps != c.wantRPS || adap != c.wantAdap {
			t.Fatalf("opsecRate(%q,%v,%d) = (%v,%d,%v)，期望 (%v,%d,%v)",
				c.opsec, c.inIval, c.inRPS, ival, rps, adap, c.wantIval, c.wantRPS, c.wantAdap)
		}
	}
}

func TestOpsecStealthNarrowsChecks(t *testing.T) {
	in := Options{Checks: "all", NucleiSubset: true, Exploit: true, DAST: true}
	out := applyOpsecChecks(in, "stealth")
	if out.Checks != "core" || out.NucleiSubset || out.Exploit || out.DAST {
		t.Fatalf("stealth 应只跑核心 check 并关闭利用级/模板池/DAST: %+v", out)
	}
	// 非 stealth 不改动（Options 含切片不可比较，逐字段核对关键项）。
	same := applyOpsecChecks(in, "balanced")
	if same.Checks != in.Checks || same.NucleiSubset != in.NucleiSubset ||
		same.Exploit != in.Exploit || same.DAST != in.DAST {
		t.Fatalf("balanced 不应改动 Options: %+v", same)
	}
}
