package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAutoUpdatePrefDefaultOn 默认开启自动更新（5.3.2 产品承诺「内置自动更新」）。
func TestAutoUpdatePrefDefaultOn(t *testing.T) {
	dir := t.TempDir()
	b := newShellBridge(nil, nil, dir, filepath.Join(dir, "state"))
	if !b.GetAutoUpdate() {
		t.Fatal("默认应开启自动更新")
	}
	if !b.GetInfo().AutoUpdate {
		t.Fatal("ShellInfo.auto_update 应为 true（注入给前端）")
	}
}

// TestAutoUpdatePrefPersists 关闭后写盘，重启读回 false。
func TestAutoUpdatePrefPersists(t *testing.T) {
	dir := t.TempDir()
	b := newShellBridge(nil, nil, dir, filepath.Join(dir, "state"))
	if b.SetAutoUpdate(false) {
		t.Fatal("SetAutoUpdate(false) 返回值错误")
	}
	if b.GetAutoUpdate() {
		t.Fatal("关闭后应读回 false")
	}
	// 新实例（模拟壳重启）读盘。
	b2 := newShellBridge(nil, nil, dir, filepath.Join(dir, "state"))
	if b2.GetAutoUpdate() {
		t.Fatal("偏好未持久化：重启后仍为 true")
	}
	// 文件存在且可读。
	if _, err := os.Stat(filepath.Join(dir, "shell-prefs.json")); err != nil {
		t.Fatalf("偏好文件未写入：%v", err)
	}
}

// TestAutoUpdatePrefReenable 再开启后持久化 true。
func TestAutoUpdatePrefReenable(t *testing.T) {
	dir := t.TempDir()
	b := newShellBridge(nil, nil, dir, filepath.Join(dir, "state"))
	b.SetAutoUpdate(false)
	b.SetAutoUpdate(true)
	b2 := newShellBridge(nil, nil, dir, filepath.Join(dir, "state"))
	if !b2.GetAutoUpdate() {
		t.Fatal("重新开启后重启应保持 true")
	}
}
