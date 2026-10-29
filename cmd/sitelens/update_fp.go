// update-fp 子命令：镜像 enthec/webappanalyzer（GPL-3.0）社区指纹库，
// 与精编 technologies.json 合并（精编优先），同时导出 name→CPE 映射。
// 公开数据可再生，不进仓库；合并后自动用 LoadTechnologies 全量编译验证。
//
// 下载闸：强制 https + 实测 sha256 留痕/可钉校验（见 update_guard.go）。
package main

import (
	"fmt"
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
	path, _, cleanup, err := downloadUpdate(url, 10*time.Minute, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer cleanup()
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取下载内容失败：", err)
		return 1
	}
	defer f.Close()
	cpePath := filepath.Join(filepath.Dir(techPath), "tech_cpe.json")
	st, err := fpmerge.MergeFromTar(f, techPath, cpePath)
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
