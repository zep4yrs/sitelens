// update-ehole 子命令：合并 EHole 社区指纹（中文产品向，finger.json
// 形态，2 万+ 规则/1.2 万产品）。参数为本地文件路径或 http(s) URL。
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/fpmerge"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

func updateEHoleCommand(cfg *config.Config, src string) int {
	if src == "" {
		fmt.Fprintln(os.Stderr, "用法：sitelens update-ehole <finger.json 路径或 URL>")
		return 1
	}
	techPath := cfg.Intel.TechnologiesPath
	if techPath == "" {
		techPath = "data/go/technologies.json"
	}
	var data []byte
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		client := &http.Client{Timeout: 10 * time.Minute}
		resp, err := client.Get(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, "下载失败：", err)
			return 1
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			fmt.Fprintln(os.Stderr, "下载失败：HTTP", resp.StatusCode)
			return 1
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取失败：", err)
			return 1
		}
	} else {
		var err error
		data, err = os.ReadFile(src)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取失败：", err)
			return 1
		}
	}
	st, err := fpmerge.MergeEHole(data, techPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "合并失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "合并完成：新增 %d，同名跳过 %d，无可用通道 %d；总计 %d\n",
		st.Added, st.SkippedDup, st.SkippedEmpty, st.Total)
	teched, verr := sitelens.LoadTechnologies(techPath)
	if verr != nil {
		fmt.Fprintln(os.Stderr, "合并后加载验证失败：", verr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "加载验证通过：%d 条技术\n", len(teched))
	return 0
}
