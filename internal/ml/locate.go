package ml

import (
	"os"
	"path/filepath"
)

// assetFiles 是模型资产的构成文件（相对资产目录）。缺任一即视为该目录
// 不是有效的资产目录。
var assetFiles = []string{
	"cve-tech.meta.json", "cve-tech.vocab.txt", "cve-tech.idf.f32", "cve-tech.coef.f32",
	"cwe-type.meta.json", "cwe-type.vocab.txt", "cwe-type.idf.f32", "cwe-type.coef.f32",
}

// AssetCandidates 返回模型资产候选目录（顺序即优先级）：
//  1. 配置值（相对路径相对进程 cwd，保持旧语义）；
//  2. 运行时常规路径 data/go/ml_assets；
//  3. 仓库内建 ml/models/go/ml_assets；
//  4. 可执行文件所在目录及其上级的 data/go/ml_assets 与 ml/models/go/ml_assets。
//
// 第 4 组用于兜底「进程 cwd 不是引擎/安装目录」的场景：CLI 在任意目录
// 启动、或壳/服务从不同 workdir 拉起引擎时，配置里的相对路径找不到资产，
// 但资产实际随可执行文件分发。此前 mlFor 只走 1–3、诊断只检查 1，于是出现
// 「资产明明在安装目录、诊断却报缺失/预测静默跳过」的假故障。
func AssetCandidates(cfgDir string) []string {
	out := []string{
		cfgDir,
		filepath.Join("data", "go", "ml_assets"),
		filepath.Join("ml", "models", "go", "ml_assets"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(exeDir, "data", "go", "ml_assets"),
			filepath.Join(exeDir, "..", "data", "go", "ml_assets"),
			filepath.Join(exeDir, "..", "..", "data", "go", "ml_assets"),
			filepath.Join(exeDir, "ml", "models", "go", "ml_assets"),
			filepath.Join(exeDir, "..", "ml", "models", "go", "ml_assets"),
		)
	}
	seen := make(map[string]bool, len(out))
	uniq := out[:0]
	for _, d := range out {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		uniq = append(uniq, d)
	}
	return uniq
}

// LocateAssetsDir 在候选目录中挑出第一个含全套模型资产的目录，找不到返回 ""。
//
// 历史背景：资产最初由 export_go_assets.py 导到 data/go/ml_assets/，后随
// 「模型进仓库本体」迁到 ml/models/go/ml_assets/（克隆即用）——data/go/ 下
// 只剩指纹库。运行时（engine.mlFor）与对拍测试曾各自维护候选顺序，测试漏跟
// 迁移后恒读不到 assets 而红。此处收敛为唯一来源，两端引用同一份候选表。
func LocateAssetsDir(candidates ...string) string {
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		ok := true
		for _, name := range assetFiles {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				ok = false
				break
			}
		}
		if ok {
			return dir
		}
	}
	return ""
}
