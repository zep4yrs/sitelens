// graph-read 子命令（4.0 P9）：读取 graph JSONL 并检视 / 契约自检。
//
// 用途：4.0 → 5.0 数据接口的参考读端与验收工具。
//
//	sitelens graph-read <file.graph.jsonl>             摘要（实体计数/观测态/CWE/链边）
//	sitelens graph-read <file.graph.jsonl> --self-test 契约自检（恒不变式），退出码表达
//
// 只读：不写入任何文件、不修改任何状态。
// 退出码：0=成功（自检通过）/ 1=契约违规 / 2=读取失败或用法错误。
package main

import (
	"fmt"
	"os"

	"cnb.cool/feng-qiao/sitelens/internal/model"
)

func graphReadCommand(args []string) int {
	if len(args) < 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, "用法：sitelens graph-read <file.graph.jsonl> [--self-test]")
		return 2
	}
	path := args[0]
	selfTest := false
	for _, a := range args[1:] {
		if a == "--self-test" {
			selfTest = true
		}
	}

	res, err := model.InspectGraph(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取失败：", err)
		return 2
	}
	if !res.Exists {
		fmt.Fprintln(os.Stderr, "文件不存在：", path)
		return 2
	}

	if selfTest {
		if res.OK() {
			fmt.Printf("契约自检通过：%s（%d 实体）\n", path, res.Entities)
			return 0
		}
		fmt.Fprintf(os.Stderr, "契约自检失败：%s（%d 项违规）\n", path, len(res.Problems))
		for _, p := range res.Problems {
			fmt.Fprintln(os.Stderr, "  -", p)
		}
		return 1
	}

	// 摘要：结构化 JSON 走 stdout（可管道消费），人类可读摘要走 stderr。
	out, _ := res.InspectJSON()
	fmt.Println(string(out))

	fmt.Fprintf(os.Stderr, "\nschema      : %s\n", res.Schema)
	if res.ScanID != "" {
		fmt.Fprintf(os.Stderr, "scan_id     : %s\n", res.ScanID)
	}
	if res.GeneratedAt != "" {
		fmt.Fprintf(os.Stderr, "generated_at: %s\n", res.GeneratedAt)
	}
	fmt.Fprintf(os.Stderr, "实体计数：\n")
	for _, k := range model.KnownKinds() {
		if n := res.Counts[k]; n > 0 {
			fmt.Fprintf(os.Stderr, "  %-15s %d\n", k, n)
		}
	}
	fmt.Fprintf(os.Stderr, "  %-13s %d\n", "合计", res.Entities)
	if len(res.ObservationDist) > 0 {
		fmt.Fprintf(os.Stderr, "observation 分布：%v\n", res.ObservationDist)
	}
	if len(res.ChainEdgeKinds) > 0 {
		fmt.Fprintf(os.Stderr, "链边类型：%v\n", res.ChainEdgeKinds)
	}
	if len(res.CWEs) > 0 {
		fmt.Fprintf(os.Stderr, "CWE：%v\n", res.CWEs)
	}
	if !res.OK() {
		fmt.Fprintf(os.Stderr, "⚠ 契约违规 %d 项（建议 --self-test 查看明细）\n", len(res.Problems))
	}
	return 0
}
