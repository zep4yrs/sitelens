package nuclei

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// FetchURL 官方模板库打包下载地址（codeload 直连，无需凭据）。
const FetchURL = "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/master"

// SyncFromTar 把官方模板库 tar.gz 流镜像到 outDir/http/（按类别子目录）。
//
// 上游 2025 改版后不再有 http/ 顶层：HTTP 相关模板分布在 cves/
// vulnerabilities/exposures 等类别目录。本函数只镜像引擎可消费的
// HTTP 类别（includeTop），落盘为 outDir/http/<类别>/…；网络/DNS/SSL/
// 文件/无头浏览器等引擎不支持的类别不镜像。同时删除镜像中已不存在的
// 文件（上游会下架），多次执行收敛为镜像语义。
// 返回（保留数，删除数）。tar 根目录名任意（codeload 为 repo-branch）。
func SyncFromTar(r io.Reader, outDir string) (int, int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, 0, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	httpDir := filepath.Join(outDir, "http")
	keep := map[string]bool{} // 相对 httpDir 的斜杠路径

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, fmt.Errorf("tar: %w", err)
		}
		name := path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/"))
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		parts := strings.SplitN(name, "/", 3)
		if len(parts) < 3 || !includeTop[parts[1]] {
			continue // tar 根文件 / 未收录类别
		}
		rel := parts[1] + "/" + parts[2]
		dst := filepath.Join(httpDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return 0, 0, err
		}
		f, err := os.Create(dst)
		if err != nil {
			return 0, 0, err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return 0, 0, fmt.Errorf("写 %s: %w", rel, err)
		}
		f.Close()
		keep[rel] = true
	}
	if len(keep) == 0 {
		return 0, 0, fmt.Errorf("tar 包内未找到可镜像的模板")
	}

	// 镜像剪枝：磁盘上有、镜像里没有的 yaml 删除（含空目录清理）
	removed := 0
	var stale []string
	filepath.WalkDir(httpDir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(httpDir, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !keep[rel] {
			stale = append(stale, p)
		}
		return nil
	})
	sort.Strings(stale)
	for _, p := range stale {
		if os.Remove(p) == nil {
			removed++
		}
	}
	pruneEmptyDirs(httpDir)
	return len(keep), removed, nil
}

// includeTop 镜像收录的 HTTP 类别（上游顶层目录名 → 收录）。
// 排除：network/dns/ssl/file/headless（引擎不可执行）、token-spray
// （令牌喷洒，与无害验证定位不符）、workflows（编排元模板）。
var includeTop = map[string]bool{
	"cves":             true,
	"exposed-panels":   true,
	"technologies":     true,
	"vulnerabilities":  true,
	"misconfiguration": true,
	"exposures":        true,
	"default-logins":   true,
	"takeovers":        true,
	"miscellaneous":    true,
	"fuzzing":          true,
	"cnvd":             true,
}

// pruneEmptyDirs 自底向上删除空目录（镜像剪枝后残留）。
func pruneEmptyDirs(root string) {
	var dirs []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr == nil && d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- { // 深度优先逆序：先删子目录
		_ = os.Remove(dirs[i]) // 非空时 Remove 失败，忽略
	}
}
