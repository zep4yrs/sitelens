package rex

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// loadDumpPatterns 从仓库数据包读取全部服务指纹模式。
func loadDumpPatterns(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("../../data/intel_dump.json.gz")
	if err != nil {
		t.Skipf("数据包不可用（%v）", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	var box struct {
		Tables struct {
			ServiceFP []struct {
				Pattern string `json:"pattern"`
			} `json:"service_fp"`
		} `json:"tables"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		t.Fatalf("json: %v", err)
	}
	out := make([]string, 0, len(box.Tables.ServiceFP))
	for _, r := range box.Tables.ServiceFP {
		out = append(out, r.Pattern)
	}
	return out
}

// compileStd 标准库 RE2 编译（独立于被测代码路径）。
func compileStd(expr string) (*regexp.Regexp, error) {
	return regexp.Compile(expr)
}

// TestServiceFPZeroDrop 验收：全部服务指纹模式经 RE2→rex 双层编译
// 后零丢弃（B25）。RE2 拒收量与 rex 承接量均须在合理区间。
func TestServiceFPZeroDrop(t *testing.T) {
	rows := loadDumpPatterns(t)
	if len(rows) < 10000 {
		t.Fatalf("数据规模异常: %d", len(rows))
	}
	rejected := 0
	rexOK := 0
	for _, p := range rows {
		if p == "" {
			continue
		}
		if _, err := compileStd(p); err == nil {
			continue
		}
		rejected++
		if _, err := Compile(p); err == nil {
			rexOK++
		} else {
			t.Errorf("RE2 拒收且 rex 亦失败: %q: %v", p, err)
		}
	}
	t.Logf("总 %d 条，RE2 拒收 %d 条，rex 承接 %d 条（零丢弃）", len(rows), rejected, rexOK)
	if rejected == 0 {
		t.Fatal("RE2 拒收量为 0：数据形状与预期不符，双层回退未被检验")
	}
	if rexOK != rejected {
		t.Fatalf("存在丢弃: rex 承接 %d / RE2 拒收 %d", rexOK, rejected)
	}
}
