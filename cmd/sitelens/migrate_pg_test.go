package main

import (
	"strings"
	"testing"
)

// TestPGDSNNoPassword BUG-030 回归：口令此前被拼进 DSN 明文，且 sslmode
// 硬编码 disable。现 DSN 不含口令（经 *pgx.ConnConfig.Password 注入），
// sslmode 走配置；含空格/引号的口令也不再破坏 DSN 解析。
func TestPGDSNNoPassword(t *testing.T) {
	p := pgConnParams{
		Host: "db.internal", Port: "6543", User: "sitelens",
		Password: `p a"s's`, DBName: "sitelens_prod", SSLMode: "require",
	}
	dsn := p.dsn()
	if strings.Contains(dsn, p.Password) || strings.Contains(dsn, "p a\"") {
		t.Fatalf("DSN 不得含口令: %q", dsn)
	}
	if strings.Contains(strings.ToLower(dsn), "password=") {
		t.Fatalf("DSN 不得带口令键: %q", dsn)
	}
	if !strings.Contains(dsn, "sslmode=require") {
		t.Fatalf("sslmode 应走配置: %q", dsn)
	}
	// 解析用例：DSN 必须能被 pgx 解析，且口令随后注入 ConnConfig
	cfg, err := p.connConfig()
	if err != nil {
		t.Fatalf("DSN 解析失败: %v", err)
	}
	if cfg.Password != p.Password {
		t.Fatalf("口令应注入 ConnConfig.Password，实际 %q", cfg.Password)
	}
	if cfg.Host != "db.internal" || cfg.Port != 6543 ||
		cfg.User != "sitelens" || cfg.Database != "sitelens_prod" {
		t.Fatalf("连接参数解析错位: host=%q port=%d user=%q db=%q",
			cfg.Host, cfg.Port, cfg.User, cfg.Database)
	}
	if cfg.TLSConfig == nil {
		t.Fatal("sslmode=require 应生成 TLS 配置")
	}
}

// TestPGSSLModeFromConfig 默认 sslmode 不再是 disable，且非法值回退 prefer。
func TestPGSSLModeFromConfig(t *testing.T) {
	cases := []struct{ env, want string }{
		{"", "prefer"},                 // 缺省：优先 TLS，服务器不支持时回退（向后兼容本地 PG）
		{"disable", "disable"},         // 显式关闭仍可用（命令入口会告警）
		{"require", "require"},         // 强制 TLS
		{"VERIFY-FULL", "verify-full"}, // 大小写归一
		{"bogus", "prefer"},            // 非法值回退缺省，不静默接受
	}
	for _, c := range cases {
		t.Setenv("SLENS_DB_SSLMODE", c.env)
		dsn := pgParamsFromEnv().dsn()
		if !strings.Contains(dsn, "sslmode="+c.want) {
			t.Errorf("SLENS_DB_SSLMODE=%q 应得到 sslmode=%s，实际 %q", c.env, c.want, dsn)
		}
		if c.want != "disable" && strings.Contains(dsn, "sslmode=disable") {
			t.Errorf("默认/显式 TLS 模式下不得出现 sslmode=disable: %q", dsn)
		}
	}
}

// TestPGParamsFromEnv 连接参数全部来自环境变量（凭证只从环境读取）。
func TestPGParamsFromEnv(t *testing.T) {
	t.Setenv("SLENS_DB_HOST", "pg.example")
	t.Setenv("SLENS_DB_PORT", "6432")
	t.Setenv("SLENS_DB_USER", "migrator")
	t.Setenv("SLENS_DB_PASSWORD", "from-env")
	t.Setenv("SLENS_DB_NAME", "hist")
	t.Setenv("SLENS_DB_SSLMODE", "verify-ca")
	p := pgParamsFromEnv()
	if p.Host != "pg.example" || p.Port != "6432" || p.User != "migrator" ||
		p.Password != "from-env" || p.DBName != "hist" || p.SSLMode != "verify-ca" {
		t.Fatalf("环境变量未正确读取: %+v", p)
	}
	cfg, err := p.connConfig()
	if err != nil {
		t.Fatal(err)
	}
	// 红线：口令只在内存里的 ConnConfig，不出现在 DSN 字符串
	if strings.Contains(p.dsn(), "from-env") {
		t.Fatal("口令进了 DSN")
	}
	if cfg.Password != "from-env" {
		t.Fatal("口令未注入 ConnConfig")
	}
}
