package sitelens

// 字面量预筛索引（litindex.go）的等价性回归：
// 新实现（滚动 4 字节 key + 开放寻址表）与旧实现（fnv4 + map 查桶）在任意
// 正文上必须返回完全相同的字面量命中集合——预筛只允许「同样结果更快」。

import (
	"math/rand"
	"strings"
	"testing"
)

// legacyLitPrescreen 旧实现副本：仅作等价性 oracle（不要在生产代码里使用）。
type legacyLitPrescreen struct {
	buckets map[uint32][]string
	shorts  []string
}

func legacyFnv4(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func buildLegacyLitPrescreen(techs []*compiledTech) *legacyLitPrescreen {
	ps := &legacyLitPrescreen{buckets: map[uint32][]string{}}
	seen := map[string]bool{}
	add := func(lit string) {
		if seen[lit] {
			return
		}
		seen[lit] = true
		if len(lit) < 4 {
			ps.shorts = append(ps.shorts, lit)
			return
		}
		h := legacyFnv4(lit[:4])
		ps.buckets[h] = append(ps.buckets[h], lit)
	}
	for _, ct := range techs {
		for _, p := range ct.html {
			if p.isLit {
				add(p.lit)
			}
		}
	}
	return ps
}

func (ps *legacyLitPrescreen) scan(sLow string) map[string]bool {
	hits := map[string]bool{}
	n := len(sLow)
	for i := 0; i+4 <= n; i++ {
		for _, lit := range ps.buckets[legacyFnv4(sLow[i:i+4])] {
			if !hits[lit] && len(lit) <= n-i && sLow[i:i+len(lit)] == lit {
				hits[lit] = true
			}
		}
	}
	for _, lit := range ps.shorts {
		if strings.Contains(sLow, lit) {
			hits[lit] = true
		}
	}
	return hits
}

// assertSameLitHits 新旧命中集合必须逐字面量相等。
func assertSameLitHits(t *testing.T, name string, want, got map[string]bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: 字面量命中数不一致 want=%d got=%d", name, len(want), len(got))
	}
	for lit := range want {
		if !got[lit] {
			t.Fatalf("%s: 新实现漏报字面量 %q", name, lit)
		}
	}
}

func TestLitPrescreenScanEquivalenceCorpus(t *testing.T) {
	techs := loadTestTechs(t)
	oldPS := buildLegacyLitPrescreen(techs)
	ps := buildLitPrescreen(techs)
	corpus := testCorpusBodies(t)
	for _, name := range sortedCorpusNames(corpus) {
		sLow := strings.ToLower(corpus[name])
		assertSameLitHits(t, name, oldPS.scan(sLow), mustScanLits(t, ps, sLow))
	}
}

func TestLitPrescreenScanEquivalenceRandom(t *testing.T) {
	techs := loadTestTechs(t)
	oldPS := buildLegacyLitPrescreen(techs)
	ps := buildLitPrescreen(techs)
	// 固定种子：随机字节串覆盖 ASCII 边界（空/短/超长/无命中）
	rng := rand.New(rand.NewSource(0x5eed))
	alphabet := []byte("abcdefghijklmnopqrstuvwxyz0123456789<>/=.-_\"' \t\n")
	for i := 0; i < 64; i++ {
		n := rng.Intn(600)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		body := string(b)
		assertSameLitHits(t, "random", oldPS.scan(body), mustScanLits(t, ps, body))
	}
}

func mustScanLits(t *testing.T, ps *litPrescreen, sLow string) map[string]bool {
	t.Helper()
	lits, _ := ps.scan(sLow)
	if lits == nil {
		t.Fatalf("scan 返回 nil litHits")
	}
	return lits
}

// TestLitPrescreenGateHitsExact gateHits 必须与 strings.Contains(正文小写, 门控)
// 完全一致——门控跳过判定的正确性依赖这一点。
func TestLitPrescreenGateHitsExact(t *testing.T) {
	techs := loadTestTechs(t)
	ps := buildLitPrescreen(techs)
	// 收集索引里的全部门控字面量（html/inline 正则的旧门 + 语法树条件字面量）
	gateLits := map[string]bool{}
	for _, ct := range techs {
		for _, p := range ct.html {
			if !p.isLit && p.gate != "" {
				gateLits[p.gate] = true
			}
		}
		for _, p := range ct.inline {
			if !p.isLit && p.gate != "" {
				gateLits[p.gate] = true
			}
		}
		for _, p := range ct.html {
			if p.gateTree != nil {
				p.gateTree.literals(gateLits)
			}
		}
		for _, p := range ct.inline {
			if p.gateTree != nil {
				p.gateTree.literals(gateLits)
			}
		}
	}
	corpus := testCorpusBodies(t)
	for _, name := range sortedCorpusNames(corpus) {
		sLow := strings.ToLower(corpus[name])
		_, gateHits := ps.scan(sLow)
		for lit := range gateHits {
			if !strings.Contains(sLow, lit) {
				t.Fatalf("%s: gateHits 误报字面量 %q（正文里并不存在）", name, lit)
			}
		}
		for lit := range gateLits {
			if strings.Contains(sLow, lit) && !gateHits[lit] {
				t.Fatalf("%s: gateHits 漏报字面量 %q", name, lit)
			}
		}
	}
}

// TestLitPrescreenScanNoIndex 空索引/短正文边界不 panic 且返回空集合。
func TestLitPrescreenScanNoIndex(t *testing.T) {
	ps := &litPrescreen{}
	lits, gates := ps.scan("")
	if len(lits) != 0 || len(gates) != 0 {
		t.Fatalf("空索引应无命中: %v %v", lits, gates)
	}
	lits, gates = ps.scan("abc")
	if len(lits) != 0 || len(gates) != 0 {
		t.Fatalf("短正文应无命中: %v %v", lits, gates)
	}
}
