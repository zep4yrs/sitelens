package beacon

import (
	"strconv"
	"testing"
	"time"
)

func resetForTest() {
	Reset()
}

// 基本流：未预订回连忽略，预订后回连记录。
func TestReserveHitFlow(t *testing.T) {
	resetForTest()
	Hit("unreserved") // 未预订：忽略
	if got := Hits(); len(got) != 0 {
		t.Fatalf("未预订 token 不应记录: %v", got)
	}
	Reserve("tok-a")
	Hit("tok-a")
	got := Hits()
	if len(got) != 1 || got[0] != "tok-a" {
		t.Fatalf("预订回连应记录: %v", got)
	}
}

// 复扫 B4-②：Reset 必须连预订表一并清空——旧 token 不重新 Reserve
// 不能再命中。
func TestResetClearsIssued(t *testing.T) {
	resetForTest()
	Reserve("tok-b")
	Reset()
	Hit("tok-b")
	if got := Hits(); len(got) != 0 {
		t.Fatalf("Reset 后旧 token 复活命中: %v", got)
	}
	// 重新预订后恢复记录
	Reserve("tok-b")
	Hit("tok-b")
	if got := Hits(); len(got) != 1 {
		t.Fatalf("Reset 后重新预订应正常记录: %v", got)
	}
}

// 复扫 B4-①：预订表有界，超上限 FIFO 淘汰，不随长驻进程单调增长。
func TestIssuedCapFIFO(t *testing.T) {
	resetForTest()
	Reserve("oldest")
	for i := 0; i < maxIssued; i++ {
		Reserve("gen-" + strconv.Itoa(i))
	}
	// "oldest" 应已被 FIFO 淘汰：其回连不再记录
	Hit("oldest")
	if got := Hits(); len(got) != 0 {
		t.Fatalf("超限后最旧预订应被淘汰: %v", got)
	}
	// 最新预订仍有效
	Reserve("newest")
	Hit("newest")
	if got := Hits(); len(got) != 1 || got[0] != "newest" {
		t.Fatalf("最新预订应保留: %v", got)
	}
}

// 复扫 B4-③：回连记录带 TTL，过期条目在读取/写入时清理，
// 旧扫描的 token 不能在新扫描里瞬间判命中。
func TestHitTTLPrune(t *testing.T) {
	resetForTest()
	Reserve("tok-old")
	Reserve("tok-fresh")
	// 手工把 tok-old 的回连时间拨回 TTL 之前
	Hit("tok-old")
	Hit("tok-fresh")
	mu.Lock()
	hits["tok-old"] = time.Now().Add(-hitTTL - time.Minute)
	mu.Unlock()
	got := Hits()
	if len(got) != 1 || got[0] != "tok-fresh" {
		t.Fatalf("过期回连应被清理: %v", got)
	}
}
