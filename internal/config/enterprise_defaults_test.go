// 企业化 6.x 配置默认值回归：新增键默认关闭/JSON，不改变既有默认行为。
package config

import "testing"

// TestEnterpriseDefaults 新增配置项默认值 + fillDefaults 补齐语义。
func TestEnterpriseDefaults(t *testing.T) {
	d := Default()
	if d.Store.Driver != "json" {
		t.Fatalf("store.driver 默认应为 json，实际 %q", d.Store.Driver)
	}
	if d.Store.DSN != "" {
		t.Fatalf("store.dsn 默认应为空，实际 %q", d.Store.DSN)
	}
	if d.Web.AuthMode != "none" {
		t.Fatalf("web.auth_mode 默认应为 none，实际 %q", d.Web.AuthMode)
	}
	if d.Web.AuthSecret != "" {
		t.Fatalf("web.auth_secret 默认应为空，实际非空")
	}
	if d.Batch.UseWorkerPool {
		t.Fatal("batch.use_worker_pool 默认应为 false")
	}

	// 零值配置经 fillDefaults 回填默认（保持旧行为）
	c := &Config{}
	c.fillDefaults()
	if c.Store.Driver != "json" || c.Web.AuthMode != "none" || c.Batch.UseWorkerPool {
		t.Fatalf("fillDefaults 未回填企业化默认值: driver=%q mode=%q pool=%v",
			c.Store.Driver, c.Web.AuthMode, c.Batch.UseWorkerPool)
	}

	// 显式配置不被默认值覆盖
	c2 := &Config{Store: StoreConfig{Driver: "postgres"}, Web: WebConfig{AuthMode: "token"}}
	c2.fillDefaults()
	if c2.Store.Driver != "postgres" || c2.Web.AuthMode != "token" {
		t.Fatalf("显式配置被覆盖: driver=%q mode=%q", c2.Store.Driver, c2.Web.AuthMode)
	}
}
