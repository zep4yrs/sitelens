package nuclei

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestTar 构造一个模板库 tar.gz：根目录名任意 + http/ 子树两个
// 版本文件 + 一个 http 外的干扰文件。
func buildTestTar(t *testing.T, entries map[string]string) string {
	t.Helper()
	raw := filepath.Join(t.TempDir(), "tpl.tar.gz")
	f, err := os.Create(raw)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestSyncFromTarMirror 镜像语义：新增/更新/剪枝三行为一次性完成。
func TestSyncFromTarMirror(t *testing.T) {
	out := t.TempDir()
	// 预置一个"上游已下架"的旧文件，应被剪枝
	stale := filepath.Join(out, "http", "old", "stale.yaml")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("id: stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tarball := buildTestTar(t, map[string]string{
		"nuclei-templates-master/cves/a.yaml":         "id: a\n",
		"nuclei-templates-master/technologies/b.yaml": "id: b\n",
		"nuclei-templates-master/dns/c.yaml":          "id: c\n", // 未收录类别：不进镜像
		"nuclei-templates-master/README.md":           "readme",  // 非 yaml：跳过
	})
	f, err := os.Open(tarball)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	kept, removed, err := SyncFromTar(f, out)
	if err != nil {
		t.Fatalf("SyncFromTar: %v", err)
	}
	if kept != 2 || removed != 1 {
		t.Fatalf("保留/剪枝计数错误: kept=%d removed=%d", kept, removed)
	}
	for _, p := range []string{
		filepath.Join(out, "http", "cves", "a.yaml"),
		filepath.Join(out, "http", "technologies", "b.yaml"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("镜像文件缺失: %s", p)
		}
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("已下架文件应被剪枝")
	}
	if _, err := os.Stat(filepath.Join(out, "dns")); !os.IsNotExist(err) {
		t.Fatalf("http 外子树不应进镜像")
	}
}

// TestSyncFromTarSecondRun 幂等：二次镜像无增无删。
func TestSyncFromTarSecondRun(t *testing.T) {
	out := t.TempDir()
	tarball := buildTestTar(t, map[string]string{
		"repo-main/cves/x/y.yaml": "id: y\n",
	})
	for round := 1; round <= 2; round++ {
		f, err := os.Open(tarball)
		if err != nil {
			t.Fatal(err)
		}
		kept, removed, err := SyncFromTar(f, out)
		f.Close()
		if err != nil {
			t.Fatalf("round%d: %v", round, err)
		}
		if kept != 1 || removed != 0 {
			t.Fatalf("round%d 应 kept=1 removed=0: %d/%d", round, kept, removed)
		}
	}
}

// TestSyncFromTarBadInput 坏输入：非 gzip 报错不 panic。
func TestSyncFromTarBadInput(t *testing.T) {
	if _, _, err := SyncFromTar(strings.NewReader("not a gzip"), t.TempDir()); err == nil {
		t.Fatal("非 gzip 输入应报错")
	}
}
