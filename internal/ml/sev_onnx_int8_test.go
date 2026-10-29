// sev_onnx_int8_test.go BUG-035「包体瘦身」实测脚手架：sev-prior v3.1 双模型
// 的 int8 量化精度损失测量（构建标签 onnx）。
//
// 背景（docs/bug清单-5.1.0.md BUG-035）：安装包 891.4MB 中 ML 资产 748.9MB，
// 4 个 ONNX 合计 643.3MB —— fp32 双模型 511.0MiB + int8 双模型 132.2MiB 整套
// 随包分发，而推理只需一套。internal/engine/ml.go:91-98 的模型 glob 顺序是
// fp32 对 → int8 对 → 旧单文件，即「只带 int8」当下就能被引擎选中、无需改代码；
// 要拍板删 fp32，先得量化 int8 的精度代价 —— 本测试就是这个测量。
//
// 口径：同一进程内加载两套打分器（sev_onnx.go 的 ortOnce 只初始化运行时环境
// 一次，session 是 per-scorer 的，可并存），用同一个 SevScorer.Score 接口跑完
// sev-fixtures.json 的全部夹具，输出三组对比（全部为 CVSS 0-10 分尺度）：
//
//	fp32(Go) vs 夹具真值(Python fp32 集成)  环境自检（TestSevOnnxParity 口径 <0.03）
//	int8(Go) vs fp32(Go)                    纯量化误差（同分词器，只差权重精度）
//	int8(Go) vs 夹具真值                    端到端误差
//
// 以及分档翻转率：1 分档 / CVSS 定性档（边界 4/7/9，同 ml/train_sev_mae.py 的
// EDGES）/ 显示位（0.1 分，结果页按 1 位小数呈现 sev_score，web/app.js:544-546）。
//
// 门槛：默认只断言「灾难上界」MAE < 0.30 分（SITLENS_INT8_MAX_MAE 可覆盖），
// 先出数据；推荐门槛与决策矩阵见 docs/release-5.2.0/ML-包体瘦身实测方案-5.2.0.md。
// 资产/DLL 缺失时 t.Skip，不影响无 onnx 环境的 `go test ./internal/ml`。
//
// 运行（需 CGO + gcc、onnxruntime.dll、models 资产；本机 CGO_ENABLED=0 跑不了）：
//
//	$env:CGO_ENABLED="1"; $env:SITLENS_ORT_DLL="D:\...\models\onnxruntime\onnxruntime.dll"
//	go test -tags onnx ./internal/ml -run TestSevOnnxInt8VsFp32 -v -timeout 10m
//
// 前置缺失时默认跳过；测量机设 SITLENS_INT8_MEASURE_REQUIRED=1 改为失败（避免
// 「跳过当成通过」）。内存：4 个 session 常驻约 1.2GiB（fp32 双模型约 536MiB
// 权重 + int8 约 139MiB + 运行时开销），建议 8GB 以上机器；120 条夹具 CPU 推理
// 约 1-3 分钟（视 CPU）。
//
//go:build onnx

package ml

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// int8DefaultMaxMAE 默认「灾难上界」（CVSS 分）：MAE 超过它说明量化出了事故
	// （例如把分类头也量化坏了），先看翻转样例再谈方案，而不是继续调门槛。
	// 参考：Python 侧导出闸门为 int8 logits MAE < 0.05（= 0.50 分），此处放宽到
	// 0.30 分只拦事故、不承担精度决策（决策见方案文档 §5）。
	int8DefaultMaxMAE = 0.30
	// int8DisplayDigits 结果页 sev_score 的小数位（web/app.js:546 toFixed(1)）。
	int8DisplayDigits = 1
	int8MiB           = 1024 * 1024
	// int8MaxSamples 每类翻转/样例日志最多打印几条，避免刷屏。
	int8MaxSamples = 5
)

// int8FixtureItem sev-fixtures.json 的一条夹具：text + Python 侧 fp32 集成分
// （0-10 CVSS 尺度，由 ml/export_sev_v31_pair.py 以 sev_score = logits×10 写入）。
type int8FixtureItem struct {
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

// int8FixtureFile sev-fixtures.json 顶层结构（seq/n/items/ensemble）。
type int8FixtureFile struct {
	Seq      int               `json:"seq"`
	N        int               `json:"n"`
	Ensemble string            `json:"ensemble"`
	Items    []int8FixtureItem `json:"items"`
}

// int8ErrStats 一组绝对误差（CVSS 分尺度）的统计量。
type int8ErrStats struct {
	N                              int
	MAE                            float64
	RMSE                           float64
	Max                            float64
	P95                            float64
	Over01, Over03, Over05, Over10 int // 绝对误差 > 0.1 / 0.3 / 0.5 / 1.0 分的条数
}

// int8AbsErr 逐条绝对误差（长度取两切片较小者）。
func int8AbsErr(got, want []float64) []float64 {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	ds := make([]float64, n)
	for i := 0; i < n; i++ {
		ds[i] = math.Abs(got[i] - want[i])
	}
	return ds
}

// int8Summarize 统计 MAE / RMSE / max / p95 / 超阈条数。
func int8Summarize(got, want []float64) int8ErrStats {
	ds := int8AbsErr(got, want)
	st := int8ErrStats{N: len(ds)}
	if st.N == 0 {
		return st
	}
	var sum, sq float64
	for _, d := range ds {
		sum += d
		sq += d * d
		if d > st.Max {
			st.Max = d
		}
		switch {
		case d > 1.0:
			st.Over10++
			fallthrough
		case d > 0.5:
			st.Over05++
			fallthrough
		case d > 0.3:
			st.Over03++
			fallthrough
		case d > 0.1:
			st.Over01++
		}
	}
	st.MAE = sum / float64(st.N)
	st.RMSE = math.Sqrt(sq / float64(st.N))
	sorted := append([]float64(nil), ds...)
	sort.Float64s(sorted)
	idx := int(math.Ceil(0.95*float64(st.N))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= st.N {
		idx = st.N - 1
	}
	st.P95 = sorted[idx]
	return st
}

// sevBandFunc 返回 CVSS 定性档名（边界 4/7/9，与 ml/train_sev_mae.py 的
// EDGES=[4.0,7.0,9.0]、web 呈现的区间语义同口径；0 分归 none）。
func sevBandFunc(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// sevPointBucketFunc 1 分档（四舍五入到整数 0-10）。
func sevPointBucketFunc(score float64) string {
	v := int(math.Round(score))
	if v < 0 {
		v = 0
	}
	if v > 10 {
		v = 10
	}
	return strconv.Itoa(v)
}

// sevDisplayBucketFunc 显示位档：按结果页 1 位小数呈现后的字符串比较，
// 用来回答「用户看到的分数变了没有」。
func sevDisplayBucketFunc(score float64) string {
	p := math.Pow(10, float64(int8DisplayDigits))
	return strconv.FormatFloat(math.Round(score*p)/p, 'f', int8DisplayDigits, 64)
}

// int8Flips 统计两个打分序列在给定分档函数下的不一致条数，并返回最多 keep
// 条样例下标（按首次出现顺序）。
func int8Flips(a, b []float64, bucket func(float64) string, keep int) (int, []int) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var samples []int
	flips := 0
	for i := 0; i < n; i++ {
		if bucket(a[i]) == bucket(b[i]) {
			continue
		}
		flips++
		if len(samples) < keep {
			samples = append(samples, i)
		}
	}
	return flips, samples
}

// int8Preview 截断夹具文本用于日志（按 rune 截，不切坏 UTF-8）。
func int8Preview(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// int8ORTDLL 解析 onnxruntime 共享库路径，口径与 sev_onnx_parity_test.go 一致：
// 环境变量 SITLENS_ORT_DLL → data/onnxruntime → models/onnxruntime（仓库内建）。
// 都找不到时返回最后候选，由调用方统一按「前置缺失」处理。
func int8ORTDLL(root string) string {
	if dll := os.Getenv("SITLENS_ORT_DLL"); dll != "" {
		return dll
	}
	cands := []string{
		filepath.Join(root, "data", "onnxruntime", "onnxruntime.dll"),
		filepath.Join(root, "models", "onnxruntime", "onnxruntime.dll"),
	}
	for _, cand := range cands {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return cands[len(cands)-1]
}

// TestSevOnnxInt8VsFp32 BUG-035 核心测量：同一进程内跑 fp32 双模型与 int8 双
// 模型，输出纯量化误差与分档翻转率，并对「灾难上界」做宽松断言。
//
// 注意：本测试不修改任何非测试代码——sev_onnx.go 的 ortOnce 只保护运行时环境
// 初始化，NewSevScorer 每次调用各自创建 session，两套并存是被支持的形态。
func TestSevOnnxInt8VsFp32(t *testing.T) {
	root := filepath.Join("..", "..")
	assets := LocateAssetsDir(
		filepath.Join(root, "data", "go", "ml_assets"),
		filepath.Join(root, "models", "go", "ml_assets"),
	)

	// 测量机：前置缺失不该被当成「通过」，用环境变量把跳过切成失败。
	required := os.Getenv("SITLENS_INT8_MEASURE_REQUIRED") == "1"
	skip := func(format string, args ...any) {
		t.Helper()
		if required {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}

	if assets == "" {
		skip("ml 资产目录缺失（data/go/ml_assets 与 models/go/ml_assets 均无成套线性模型），跳过 int8 实测")
	}

	vocabPath := filepath.Join(assets, "sev-prior-v3.1.vocab.txt")
	fixPath := filepath.Join(assets, "sev-fixtures.json")
	fp32Paths := []string{
		filepath.Join(assets, "sev-prior-v3.1-a.onnx"),
		filepath.Join(assets, "sev-prior-v3.1-b.onnx"),
	}
	int8Paths := []string{
		filepath.Join(assets, "sev-prior-v3.1-a-int8.onnx"),
		filepath.Join(assets, "sev-prior-v3.1-b-int8.onnx"),
	}
	dll := int8ORTDLL(root)

	need := []string{vocabPath, fixPath, dll}
	need = append(need, fp32Paths...)
	need = append(need, int8Paths...)
	var missing []string
	for _, p := range need {
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		skip("int8 实测前置缺失（%s），跳过；补齐方法与一键命令见 docs/release-5.2.0/ML-包体瘦身实测方案-5.2.0.md",
			strings.Join(missing, "; "))
	}
	// 资产指纹（字节数）——与方案文档体积表对账，避免测错文件。
	var total int64
	for _, p := range append(append([]string{}, fp32Paths...), int8Paths...) {
		fi, err := os.Stat(p)
		if err != nil {
			skip("onnx 资产读取失败（%s）: %v", p, err)
		}
		total += fi.Size()
		t.Logf("资产 %-32s %12d B (%7.2f MiB)", filepath.Base(p), fi.Size(), float64(fi.Size())/int8MiB)
	}
	t.Logf("四件 ONNX 合计 %d B (%.2f MiB)；预期 fp32 对 511.0 MiB + int8 对 132.2 MiB", total, float64(total)/int8MiB)

	raw, err := os.ReadFile(fixPath)
	if err != nil {
		t.Fatalf("读取 sev-fixtures.json 失败（%s）: %v", fixPath, err)
	}
	var fix int8FixtureFile
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("解析 sev-fixtures.json: %v", err)
	}
	if len(fix.Items) < 20 {
		skip("夹具仅 %d 条（<20），统计量不可用，跳过", len(fix.Items))
	}
	if fix.Seq != 192 {
		t.Logf("警告：夹具 seq=%d，推理侧固定 seq=192（分词器按 192 截断/填充），可能影响可比性", fix.Seq)
	}
	t.Logf("夹具 n=%d ensemble=%q（真值 = Python 侧 fp32 双模型集成 ×10 CVSS 分）", len(fix.Items), fix.Ensemble)

	// 两套打分器并存：ort 环境进程内只初始化一次，session 各自独立。
	tLoad := time.Now()
	t.Logf("加载 fp32 双模型（约 536 MiB 权重）…")
	fp32, err := NewSevScorer(vocabPath, dll, fp32Paths)
	if err != nil {
		skip("fp32 scorer 初始化失败（环境问题，不是精度结论）：%v", err)
	}
	t.Logf("fp32 双模型就绪（%v）；加载 int8 双模型（约 139 MiB 权重）…", time.Since(tLoad).Round(time.Millisecond))
	int8s, err := NewSevScorer(vocabPath, dll, int8Paths)
	if err != nil {
		skip("int8 scorer 初始化失败（环境问题，不是精度结论）：%v", err)
	}
	t.Logf("int8 双模型就绪；两套 session 常驻（总加载 %v，内存约 1.2GiB）", time.Since(tLoad).Round(time.Millisecond))

	n := len(fix.Items)
	truth := make([]float64, n)
	for i := range fix.Items {
		truth[i] = fix.Items[i].Score
	}
	gotFP32 := make([]float64, n)
	gotINT8 := make([]float64, n)

	t0 := time.Now()
	for i := range fix.Items {
		s, err := fp32.Score(fix.Items[i].Text)
		if err != nil {
			t.Fatalf("fp32 推理第 %d 条失败：%v", i, err)
		}
		gotFP32[i] = s
	}
	fp32Dur := time.Since(t0)
	t0 = time.Now()
	for i := range fix.Items {
		s, err := int8s.Score(fix.Items[i].Text)
		if err != nil {
			t.Fatalf("int8 推理第 %d 条失败：%v", i, err)
		}
		gotINT8[i] = s
	}
	int8Dur := time.Since(t0)
	t.Logf("推理耗时（双模型各一次、取平均）：fp32 共 %v（%.1f ms/条）；int8 共 %v（%.1f ms/条）",
		fp32Dur.Round(time.Millisecond), float64(fp32Dur)/float64(time.Millisecond)/float64(n),
		int8Dur.Round(time.Millisecond), float64(int8Dur)/float64(time.Millisecond)/float64(n))

	// 1) 环境自检：Go fp32 vs Python fp32 真值。口径偏大时先怀疑资产/分词器，
	//    而不是把端到端差值当成量化损失。
	stSelf := int8Summarize(gotFP32, truth)
	t.Logf("[自检] fp32(Go) vs 夹具真值: n=%d MAE=%.4f max=%.4f（TestSevOnnxParity 口径 <0.03）",
		stSelf.N, stSelf.MAE, stSelf.Max)
	if stSelf.MAE >= 0.03 {
		t.Logf("警告：fp32 自检 MAE=%.4f ≥ 0.03，先跑 TestSevOnnxParity 查环境；下面的纯量化差仍可比（同分词器），端到端值请谨慎引用", stSelf.MAE)
	}

	// 2) 纯量化误差：同一分词器、同一推理路径，只换权重精度。
	stQ := int8Summarize(gotINT8, gotFP32)
	t.Logf("[量化] int8 vs fp32（纯量化误差）: n=%d MAE=%.4f RMSE=%.4f max=%.4f p95=%.4f",
		stQ.N, stQ.MAE, stQ.RMSE, stQ.Max, stQ.P95)
	t.Logf("       绝对误差分布：>0.1 分 %d 条 / >0.3 分 %d 条 / >0.5 分 %d 条 / >1.0 分 %d 条",
		stQ.Over01, stQ.Over03, stQ.Over05, stQ.Over10)
	t.Logf("       折算 logits(0-1) 尺度 MAE=%.5f（Python 导出闸门 int8<0.05，实测 0.0127，来源 docs/release-5.0.0/TRAINING_PARAMS.md §3.9）",
		stQ.MAE/10)

	// 3) 端到端：int8(Go) vs Python fp32 真值。
	stE := int8Summarize(gotINT8, truth)
	t.Logf("[端到端] int8(Go) vs 夹具真值: n=%d MAE=%.4f max=%.4f p95=%.4f",
		stE.N, stE.MAE, stE.Max, stE.P95)

	// 4) 分档翻转率（诊断项：结果页是「分数 ± 1.07 区间」，不做硬档位）。
	for _, c := range []struct {
		name   string
		bucket func(float64) string
	}{
		{"1 分档", sevPointBucketFunc},
		{"CVSS 定性档(4/7/9)", sevBandFunc},
		{"显示位 0.1 分", sevDisplayBucketFunc},
	} {
		flips, samples := int8Flips(gotINT8, gotFP32, c.bucket, int8MaxSamples)
		t.Logf("[翻转] %-18s int8 vs fp32: %d/%d = %.2f%%", c.name, flips, n, 100*float64(flips)/float64(n))
		for _, i := range samples {
			t.Logf("        #%03d fp32=%6.3f int8=%6.3f Δ=%+.3f | %s",
				i, gotFP32[i], gotINT8[i], gotINT8[i]-gotFP32[i], int8Preview(fix.Items[i].Text, 70))
		}
	}

	// 最大偏差样例（不看分档，直接暴露最坏条）。
	ds := int8AbsErr(gotINT8, gotFP32)
	order := make([]int, len(ds))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return ds[order[a]] > ds[order[b]] })
	t.Logf("[样例] int8 vs fp32 绝对误差最大的 %d 条：", int8MaxSamples)
	for k := 0; k < int8MaxSamples && k < len(order); k++ {
		i := order[k]
		t.Logf("        #%03d Δ=%.3f（fp32 %.3f → int8 %.3f）| %s",
			i, ds[i], gotFP32[i], gotINT8[i], int8Preview(fix.Items[i].Text, 70))
	}

	// 5) 宽松门：默认只拦「量化事故」，可用 SITLENS_INT8_MAX_MAE 覆盖；
	//    推荐门槛（0.15 分）与决策矩阵见方案文档 §5，不在此断言。
	maxMAE := int8DefaultMaxMAE
	if v := os.Getenv("SITLENS_INT8_MAX_MAE"); v != "" {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f <= 0 {
			t.Fatalf("SITLENS_INT8_MAX_MAE=%q 不是正数", v)
		}
		maxMAE = f
	}
	if stQ.MAE >= maxMAE {
		t.Fatalf("int8 vs fp32 MAE=%.4f ≥ 上界 %.2f 分：量化疑似事故，先看上面的翻转样例，再决定是否退回方案②按需下载",
			stQ.MAE, maxMAE)
	}
	t.Logf("结论：纯量化 MAE=%.4f 分 < 灾难上界 %.2f 分，通过。推荐门槛：MAE≤0.15 且 p95≤0.30 且 max≤0.60 → 方案① int8 优先；否则方案②按需下载（见方案文档 §5）",
		stQ.MAE, maxMAE)
}
