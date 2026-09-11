// update-fp 子命令：镜像 enthec/webappanalyzer（GPL-3.0）社区指纹库，
// 与精编 technologies.json 合并（精编优先），同时导出 name→CPE 映射。
// 公开数据可再生，不进仓库；合并后自动用 LoadTechnologies 全量编译验证。
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/fpmerge"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

func updateFPCommand(cfg *config.Config, url string) int {
	techPath := cfg.Intel.TechnologiesPath
	if techPath == "" {
		techPath = "data/go/technologies.json"
	}
	if url == "" {
		url = fpmerge.FetchURL
	}
	fmt.Fprintf(os.Stderr, "下载社区指纹库：%s\n", url)
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "下载失败：", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintln(os.Stderr, "下载失败：HTTP", resp.StatusCode)
		return 1
	}
	cpePath := filepath.Join(filepath.Dir(techPath), "tech_cpe.json")
	st, err := fpmerge.MergeFromTar(resp.Body, techPath, cpePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "合并失败：", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "合并完成：新增 %d，同名跳过 %d，无可用通道 %d，拒绝模式 %d；总计 %d\n",
		st.Added, st.SkippedDup, st.SkippedEmpty, st.RejectedPats, st.Total)
	teched, verr := sitelens.LoadTechnologies(techPath)
	if verr != nil {
		fmt.Fprintln(os.Stderr, "合并后加载验证失败：", verr)
		return 1
	}
	fmt.Fprintf(os.Stderr, "加载验证通过：%d 条技术（CPE 映射 %d 条 → %s）\n",
		len(teched), st.CPEs, cpePath)
	return 0
}
