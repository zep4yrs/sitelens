package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultSane(t *testing.T) {
	c := Default()
	if c.Scan.RateIntervalMS != 400 || c.Scan.MaxConcurrent != 3 {
		t.Fatalf("Scan 默认值不符: %+v", c.Scan)
	}
	if c.Web.Listen == "" || c.Intel.DumpPath == "" {
		t.Fatalf("路径类默认值不能为空")
	}
	if c.DAST.BlindThresholdMS != 3500 {
		t.Fatalf("DAST 默认阈值不符: %+v", c.DAST)
	}
}

func TestLoadMissingFile(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yml"))
	if err != nil {
		t.Fatalf("文件不存在应静默用默认: %v", err)
	}
	if c.Scan.TimeoutSec != 15 {
		t.Fatalf("默认 TimeoutSec 应为 15: %d", c.Scan.TimeoutSec)
	}
}

func TestLoadPartialOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sitelens.yml")
	yml := `
scan:
  rate_interval_ms: 100
dast:
  max_params: 8
  time_blind: false
web:
  listen: "0.0.0.0:8000"
`
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	// 覆盖项生效
	if c.Scan.RateIntervalMS != 100 || c.DAST.MaxParams != 8 || !c.DAST.TimeBlind == false {
		t.Fatalf("覆盖项未生效: %+v %+v", c.Scan, c.DAST)
	}
	if c.Web.Listen != "0.0.0.0:8000" {
		t.Fatalf("listen 未生效: %s", c.Web.Listen)
	}
	// 未覆盖项回退默认（零值回退）
	if c.Scan.TimeoutSec != 15 || c.Batch.Workers != 3 || c.DAST.SleepSeconds != 4 {
		t.Fatalf("未覆盖项应回退默认: %+v", c)
	}
}

func TestNegativeFallsBack(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sitelens.yml")
	yml := "scan:\n  timeout_sec: -5\nbatch:\n  workers: -1\n"
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Scan.TimeoutSec != 15 || c.Batch.Workers != 3 {
		t.Fatalf("负值应回退默认: %d %d", c.Scan.TimeoutSec, c.Batch.Workers)
	}
}

func TestBoolFalseIsLegal(t *testing.T) {
	// 布尔 false 是合法的"关"，不应被回退成默认的"开"
	c := LoadOrDefault(filepath.Join(t.TempDir(), "nope.yml"))
	if !c.DAST.TimeBlind || !c.Crawler.RespectRobots {
		t.Fatal("默认应为开")
	}
}

// TestUnknownTopKeyWarn 未知顶层键必须被检出（crawl: vs crawler: 一字之差
// 曾导致整段爬虫配置静默失效）。
func TestUnknownTopKeyWarn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yml")
	cfgYAML := "crawler:\n  max_pages: 30\ncrawl:\n  max_pages: 99\n"
	if err := os.WriteFile(path, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	unknown := unknownTopKeys([]byte(cfgYAML))
	if len(unknown) != 1 || unknown[0] != "crawl" {
		t.Fatalf("应检出未知键 crawl: %v", unknown)
	}
	cfg := LoadOrDefault(path)
	if cfg.Crawler.MaxPages != 30 {
		t.Fatalf("crawler.max_pages 应生效: %d", cfg.Crawler.MaxPages)
	}
}

// TestUpsertYAMLTypes upsert 写回的值必须保留类型（int/bool），
// 否则重新解析时 int 字段失败并整体回退默认。
func TestUpsertYAMLTypes(t *testing.T) {
	base := []byte("crawler:\n  max_pages: 4\n  respect_robots: true\nscan:\n  rate_interval_ms: 400\n")
	out, err := UpsertYAMLSections(base, map[string]map[string]any{
		"crawler": {"max_pages": 31, "respect_robots": false},
		"checks":  {"nuclei_cap": 310},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("写回 yml 解析失败: %v", err)
	}
	if cfg.Crawler.MaxPages != 31 || cfg.Crawler.RespectRobots {
		t.Fatalf("爬取值错误: %+v", cfg.Crawler)
	}
	if cfg.Checks.NucleiCap != 310 {
		t.Fatalf("checks 段 upsert 失败: %+v", cfg.Checks)
	}
	if cfg.Scan.RateIntervalMS != 400 {
		t.Fatalf("未纳管键应保留: %d", cfg.Scan.RateIntervalMS)
	}
}
