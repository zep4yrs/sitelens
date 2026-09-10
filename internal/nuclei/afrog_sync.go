// afrog POC 库同步：拉取 afrog 主仓 zip（codeload 直链），把 Pocs/**
// 下的 YAML 镜像到 nuclei_dir/afrog/——引擎索引与加载对同目录 YAML
// 统一走三前端漏斗（path/raw/afrog 经典），无需单独索引链路。
package nuclei

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AfrogFetchURL afrog 主仓 main 分支 zip（codeload 直链）。
const AfrogFetchURL = "https://codeload.github.com/affrog/afrog/zip/refs/heads/main"

// afrogZipEntryCap zip 条目总量上限（对齐 server.extractZip 的防御语义）。
const afrogZipEntryCap = 2000

// afrogFileCap 单文件解压上限（POC YAML 远小于此值，防御性设定）。
const afrogFileCap = 1 << 20

// SyncAfrogFromZip 从 afrog 仓 zip 镜像 Pocs/** 到 outDir/afrog/。
// 先清空旧 afrog 目录（removed 计数）再落新文件；路径含 .. 或绝对
// 路径的条目直接报错（zip-slip 防御）。
func SyncAfrogFromZip(buf []byte, outDir string) (kept, removed int, err error) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return 0, 0, fmt.Errorf("zip 打开失败: %w", err)
	}
	target := filepath.Join(outDir, "afrog")
	if entries, _ := os.ReadDir(target); len(entries) > 0 {
		if err := os.RemoveAll(target); err != nil {
			return 0, 0, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				removed++
			}
		}
	}
	for _, f := range zr.File {
		if kept >= afrogZipEntryCap {
			break // 防御性截断（afrog POC 总量远小于此）
		}
		name := filepath.ToSlash(f.Name)
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		// 剥掉仓库根前缀（afrog-main/），只收 Pocs/** 分类目录
		rel := name
		if i := strings.Index(name, "/Pocs/"); i >= 0 {
			rel = "Pocs/" + name[i+len("/Pocs/"):]
		} else {
			continue
		}
		if strings.Contains(rel, "..") || filepath.IsAbs(rel) {
			return kept, removed, fmt.Errorf("zip 内不安全路径: %s", name)
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(rc, afrogFileCap+1))
		rc.Close()
		if rerr != nil || len(data) == 0 || len(data) > afrogFileCap {
			continue
		}
		dst := filepath.Join(target, filepath.FromSlash(strings.TrimPrefix(rel, "Pocs/")))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return kept, removed, err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return kept, removed, err
		}
		kept++
	}
	return kept, removed, nil
}
