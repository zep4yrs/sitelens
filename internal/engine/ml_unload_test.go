package engine

import (
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// TestInvalidateMLIdempotent 未加载时调用必须安全且幂等（C2-10 引擎接线）。
func TestInvalidateMLIdempotent(t *testing.T) {
	e := New(config.Default(), nil, nil)
	e.InvalidateML()
	e.InvalidateML() // 幂等：第二次不 panic、不清空不存在的资产
}

// TestInvalidateMLUnloadsLoadedAssets AI 总闸关闭后底层 ~94MB 系数必须真正
// 释放（即使调用方仍持有旧 *Assets），释放幂等，且下次需要时能按需重建。
func TestInvalidateMLUnloadsLoadedAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("加载 ML 资产需读 ~94MB 文件，-short 跳过")
	}
	e := New(config.Default(), nil, nil)
	a := e.mlFor()
	if a == nil || !a.Loaded() {
		t.Skip("本机无 ML 资产或加载失败（mlDead），跳过")
	}
	e.InvalidateML()
	if a.Loaded() {
		t.Fatalf("InvalidateML 后底层资产应已释放（外部持有的旧 *Assets 也不应再占着系数）")
	}
	e.InvalidateML() // 幂等
	again := e.mlFor()
	if again == nil || !again.Loaded() {
		t.Fatalf("释放后按需重建失败（下次扫描会静默丢失 ML 富化）")
	}
	if again == a {
		t.Fatalf("应重建为新的 Assets 实例")
	}
}
