package modules

import (
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

func testActiveCfg() config.ActiveConfig {
	return config.ActiveConfig{TakeoverMax: 50}
}

// TestTakeoverProbeHit CNAME 命中 + 特征页命中 = 输出接管信号。
func TestTakeoverProbeHit(t *testing.T) {
	subs := []string{"lcm20.example.com", "blog.example.com"}
	res := TakeoverProbeWith(subs, testActiveCfg(), nil, nil,
		func(host string) (string, error) {
			if host == "lcm20.example.com" {
				return "lcm20.github.io.", nil
			}
			return "web.example.com.", nil // 普通 CNAME，不匹配签名
		},
		func(url string) (int, string, error) {
			if strings.HasPrefix(url, "https://lcm20.") {
				return 404, "<html>There isn't a GitHub Pages site here.</html>", nil
			}
			return 200, "<html>normal site</html>", nil
		})
	if len(res) != 1 {
		t.Fatalf("应命中 1 条接管信号: %+v", res)
	}
	if res[0].Sub != "lcm20.example.com" || res[0].Service != "GitHub Pages" {
		t.Fatalf("命中对象错误: %+v", res[0])
	}
	if res[0].Severity != "high" || res[0].Evidence == "" || res[0].Advice == "" {
		t.Fatalf("字段不完整: %+v", res[0])
	}
}

// TestTakeoverProbeDoubleCondition 双条件缺一不可：
// CNAME 命中但特征页不中（已重新绑定）→ 不报；特征页撞车但 CNAME 不匹配 → 不报。
func TestTakeoverProbeDoubleCondition(t *testing.T) {
	subs := []string{"a.example.com", "b.example.com"}
	res := TakeoverProbeWith(subs, testActiveCfg(), nil, nil,
		func(host string) (string, error) {
			if host == "a.example.com" {
				return "a.github.io.", nil // CNAME 命中
			}
			return "b.example.com.", nil
		},
		func(url string) (int, string, error) {
			if strings.HasPrefix(url, "https://b.") {
				return 404, "There isn't a GitHub Pages site here.", nil // 特征撞车
			}
			return 200, "<html>welcomed</html>", nil
		})
	if len(res) != 0 {
		t.Fatalf("单条件命中不应输出: %+v", res)
	}
}

// TestTakeoverProbeCap 候选上限生效（TakeoverMax 截断）。
func TestTakeoverProbeCap(t *testing.T) {
	cfg := testActiveCfg()
	cfg.TakeoverMax = 3
	probed := 0
	res := TakeoverProbeWith([]string{"1.example.com", "2.example.com", "3.example.com",
		"4.example.com", "5.example.com"}, cfg,
		func(done, total int, msg string) { probed++ },
		nil,
		func(string) (string, error) { return "x.github.io.", nil },
		func(string) (int, string, error) { return 404, "There isn't a GitHub Pages site here.", nil })
	if len(res) != 3 {
		t.Fatalf("TakeoverMax=3 应只探测 3 个: %d", len(res))
	}
	if probed != 3 {
		t.Fatalf("进度回调次数应等于探测数 3: %d", probed)
	}
}

// TestMatchTakeoverSig 签名表匹配：完整后缀与去点形态都认。
func TestMatchTakeoverSig(t *testing.T) {
	if sig := matchTakeoverSig("lcm20.github.io"); sig == nil || sig.Service != "GitHub Pages" {
		t.Fatalf("github.io 应命中 GitHub Pages: %+v", sig)
	}
	if sig := matchTakeoverSig("bucket.s3.amazonaws.com"); sig == nil || sig.Service != "AWS S3" {
		t.Fatalf("s3 后缀应命中 AWS S3: %+v", sig)
	}
	if sig := matchTakeoverSig("web.example.com"); sig != nil {
		t.Fatalf("普通 CNAME 不应命中: %+v", sig)
	}
}

// TestTakeoverProbeCancel 取消即时生效。
func TestTakeoverProbeCancel(t *testing.T) {
	res := TakeoverProbeWith([]string{"a.example.com", "b.example.com"},
		testActiveCfg(), nil, func() bool { return true },
		func(string) (string, error) { return "x.github.io.", nil },
		func(string) (int, string, error) { return 404, "There isn't a GitHub Pages site here.", nil })
	if len(res) != 0 {
		t.Fatalf("取消后不应有产出: %+v", res)
	}
}
