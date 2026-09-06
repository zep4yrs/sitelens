package checks

import "testing"

// ConfigurePlugins 幂等：重复调用不重复注入插件；空目录静默。
func TestConfigurePluginsIdempotent(t *testing.T) {
	before := len(AllChecks())
	ConfigurePlugins(t.TempDir()) // 空目录
	ConfigurePlugins(t.TempDir())
	if after := len(AllChecks()); after != before {
		t.Fatalf("空插件目录不应改变 check 数量: %d -> %d", before, after)
	}
}
