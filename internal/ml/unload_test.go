package ml

// C2-10 回归：ML 资产卸载（Unload/Close）。
//
// 契约：
//   - 幂等、并发安全：重复卸载安全；与在途推理（Predict/ProbaTopK/ArgMax/
//     RegressionScore）并发不得 panic/race；
//   - 卸载释放 94MB 级权重（即使外部仍持有 *Model 引用，也置空其内部大块数据）；
//   - 卸载后模型/资产是"空状态"：推理返回空/零结果、回归返回明确错误，不 panic；
//   - 需要重新使用时重新 LoadAssets/LoadModel 可重建。
//   - -race 用例：go test -race ./internal/ml -run TestUnloadConcurrent

import (
	"sync"
	"testing"
)

// tinyClassModel 构造一个 3 类 × 2 特征的小模型（不依赖磁盘资产）。
func tinyClassModel() *Model {
	return &Model{
		name:      "tiny-class",
		classes:   []string{"a", "b", "c"},
		vocab:     map[string]int32{"foo": 0, "bar": 1},
		idf:       []float32{1, 1},
		coef:      []float32{1, 0, 0, 1, -1, -1},
		intercept: []float64{-1, 0, 1},
		nFeatures: 2,
		nClasses:  3,
	}
}

// tinySevModel 构造一个单输出回归小模型。
func tinySevModel() *Model {
	return &Model{
		name:      "tiny-sev",
		classes:   []string{"score"},
		vocab:     map[string]int32{"foo": 0},
		idf:       []float32{1},
		coef:      []float32{2},
		intercept: []float64{5},
		nFeatures: 1,
		nClasses:  1,
	}
}

// TestModelUnloadIdempotentAndSafe 模型卸载：幂等、卸载后各推理入口安全。
func TestModelUnloadIdempotentAndSafe(t *testing.T) {
	m := tinyClassModel()
	if !m.Loaded() {
		t.Fatal("前置：模型应处于已加载状态")
	}
	if got := m.ProbaTopK("foo bar", 2); len(got) != 2 {
		t.Fatalf("卸载前应能推理，实得 %v", got)
	}

	m.Unload()
	m.Unload() // 幂等
	m.Close()
	if m.Loaded() {
		t.Fatal("卸载后 Loaded() 应为 false")
	}
	if nc, nf := m.Dims(); nc != 0 || nf != 0 {
		t.Fatalf("卸载后维度应为 (0,0)，实得 (%d,%d)", nc, nf)
	}
	if m.Classes() != nil {
		t.Fatalf("卸载后类别表应为 nil: %v", m.Classes())
	}
	// 各入口返回空/零值而非 panic。
	if got := m.ProbaTopK("foo bar", 3); len(got) != 0 {
		t.Fatalf("卸载后 ProbaTopK 应返回空: %v", got)
	}
	if got := m.TopK("foo bar", 3); len(got) != 0 {
		t.Fatalf("卸载后 TopK 应返回空: %v", got)
	}
	if got := m.DecisionFunction("foo bar"); len(got) != 0 {
		t.Fatalf("卸载后 DecisionFunction 应返回空: %v", got)
	}
	if ids, vals := m.Vectorize("foo bar"); len(ids) != 0 || len(vals) != 0 {
		t.Fatalf("卸载后 Vectorize 应返回空: %v %v", ids, vals)
	}
	if c, s := m.ArgMax("foo bar"); c != "" || s != 0 {
		t.Fatalf("卸载后 ArgMax 应返回空: %q %v", c, s)
	}
	if p := m.Proba("foo bar", "a"); p != 0 {
		t.Fatalf("卸载后 Proba 应为 0，实得 %v", p)
	}
	if _, err := m.RegressionScore("foo bar"); err == nil {
		t.Fatal("卸载后 RegressionScore 应返回明确错误")
	}
	// 空模型（零值）同样安全。
	var zero Model
	if _, err := zero.RegressionScore("x"); err == nil {
		t.Fatal("零值模型回归应返回错误")
	}
	if c, _ := zero.ArgMax("x"); c != "" {
		t.Fatalf("零值模型 ArgMax 应为空: %q", c)
	}
}

// TestAssetsUnloadAndReload 卸载释放 + 重新 Load 可重建。
func TestAssetsUnloadAndReload(t *testing.T) {
	dir := testAssetsDir(t) // 资产缺失时自动 Skip
	a, err := LoadAssets(dir)
	if err != nil {
		t.Fatalf("LoadAssets: %v", err)
	}
	if !a.Loaded() {
		t.Fatal("LoadAssets 后 Loaded() 应为 true")
	}
	tech := a.Tech // 保留外部引用：卸载必须连它的内部权重一起释放
	desc := "A buffer overflow in Apache Tomcat allows remote code execution."
	if top, cwe := a.Predict(desc); len(top) == 0 || cwe == "" {
		t.Fatalf("卸载前推理异常: top=%v cwe=%q", top, cwe)
	}

	a.Unload()
	a.Close() // 幂等
	if a.Loaded() {
		t.Fatal("卸载后 Loaded() 应为 false")
	}
	if tech.Loaded() {
		t.Fatal("即使外部仍持有 *Model，Unload 也应释放其内部权重（否则 94MB 仍常驻）")
	}
	if top, cwe := a.Predict(desc); len(top) != 0 || cwe != "" {
		t.Fatalf("卸载后 Predict 应返回空结果: top=%v cwe=%q", top, cwe)
	}
	// 重复卸载安全
	a.Unload()

	// 卸载后重新加载 → 可重建并恢复推理。
	a2, err := LoadAssets(dir)
	if err != nil {
		t.Fatalf("卸载后重新 LoadAssets 失败: %v", err)
	}
	if !a2.Loaded() {
		t.Fatal("重建后 Loaded() 应为 true")
	}
	if top, cwe := a2.Predict(desc); len(top) == 0 || cwe == "" {
		t.Fatalf("重建后推理异常: top=%v cwe=%q", top, cwe)
	}
	a2.Unload()
}

// TestUnloadConcurrentInference -race 用例：卸载与在途推理并发必须干净。
// （普通 go test 下是并发冒烟；-race 下验证锁正确性。）
func TestUnloadConcurrentInference(t *testing.T) {
	tech := tinyClassModel()
	sev := tinySevModel()
	assets := &Assets{Tech: tech, Cwe: tinyClassModel(), Sev: sev}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	readers := []func(){
		func() { assets.Predict("foo bar baz") },
		func() { tech.ProbaTopK("foo bar", 2) },
		func() { tech.ArgMax("foo bar") },
		func() { tech.TopK("foo bar", 2) },
		func() { tech.Proba("foo bar", "a") },
		func() { sev.RegressionScore("foo bar") },
	}
	for _, fn := range readers {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}(fn)
	}
	// 写侧：反复卸载（幂等），与读侧并发。
	for i := 0; i < 300; i++ {
		assets.Unload()
		tech.Unload()
		sev.Unload()
	}
	close(stop)
	wg.Wait()

	if assets.Loaded() || tech.Loaded() || sev.Loaded() {
		t.Fatal("并发卸载结束后应为未加载状态")
	}
	// 重建后仍可正常推理（证明卸载没有把对象弄坏）。
	fresh := &Assets{Tech: tinyClassModel(), Cwe: tinyClassModel(), Sev: tinySevModel()}
	if top, cwe := fresh.Predict("foo bar"); len(top) == 0 || cwe == "" {
		t.Fatalf("重建后推理异常: top=%v cwe=%q", top, cwe)
	}
}
