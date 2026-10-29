// update-ehole 子命令：合并 EHole 社区指纹（中文产品向，finger.json
// 形态，2 万+ 规则/1.2 万产品）。参数为本地文件路径或 https URL。
//
// 安全约束（BUG-023）：远程源只接受 https——指纹库直接决定识别结论，
// 明文 http 可被中间人替换。下载后输出实测 sha256 供人工核对
// （见 update_guard.go；SLENS_UPDATE_SHA256 可钉住期望摘要）。
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/config"
	"cnb.cool/feng-qiao/sitelens/internal/fpmerge"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

func updateEHoleCommand(cfg *config.Config, src string) int {
	if src == "" {
		fmt.Fprintln(os.Stderr, "用法：sitelens update-ehole <finger.json 路径或 https URL>")
		return 1
	}
	techPath := cfg.Intel.TechnologiesPath
	if techPath == "" {
		techPath = "data/go/technologies.json"
	}
	var data []byte
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		path, _, cleanup, err := downloadUpdate(src, 10*time.Minute, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer cleanup()
		data, err = os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取下载内容失败：", err)
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
