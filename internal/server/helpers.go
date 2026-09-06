// server 辅助：指纹元数据 / zip 安全解压 / 登录爆破 HTTP 适配。
package server

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// techMeta 指纹库统计元数据。
type techMeta struct {
	cats  []string
	count int
}

// loadTechMeta 读 technologies.json 的类别全集与条数（统计/CSV 用）。
func loadTechMeta(cfg *config.Config) (techMeta, error) {
	data, err := os.ReadFile(cfg.Intel.TechnologiesPath)
	if err != nil {
		return techMeta{}, err
	}
	var box struct {
		Technologies []struct {
			Name string   `json:"name"`
			Cats []string `json:"cats"`
		} `json:"technologies"`
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return techMeta{}, err
	}
	seen := map[string]bool{}
	var cats []string
	for _, t := range box.Technologies {
		for _, c := range t.Cats {
			if !seen[c] {
				seen[c] = true
				cats = append(cats, c)
			}
		}
	}
	return techMeta{cats: cats, count: len(box.Technologies)}, nil
}

// extractZip zip 安全解压：拒绝绝对路径与 .. 穿越，单文件大小受限。
func extractZip(f io.ReaderAt, size int64, dir string, maxFileBytes int64) error {
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return fmt.Errorf("无法读取 zip：%v", err)
	}
	if maxFileBytes <= 0 {
		maxFileBytes = 8 << 20
	}
	for _, zf := range zr.File {
		name := filepath.Clean(zf.Name)
		if strings.Contains(name, "..") || filepath.IsAbs(name) {
			continue // zip-slip 防护
		}
		target := filepath.Join(dir, name)
		if zf.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		dst, err := os.Create(target)
		if err != nil {
			rc.Close()
			continue
		}
		_, _ = io.Copy(dst, io.LimitReader(rc, maxFileBytes+1))
		dst.Close()
		rc.Close()
	}
	return nil
}

// httpPoster 把 httpx 客户端适配为 loginbrute.Poster。
type httpPoster struct{ c *httpx.Client }

func (h *httpPoster) GetSmall(rawURL string) (int, string, error) {
	r, err := h.c.GetDirect(rawURL)
	if err != nil || r == nil {
		return 0, "", err
	}
	return r.Status, r.Body, nil
}

func (h *httpPoster) PostForm(rawURL string, fields map[string]string) (int, string, error) {
	r, err := h.c.PostForm(rawURL, fields)
	if err != nil || r == nil {
		return 0, "", err
	}
	return r.Status, r.Body, nil
}
