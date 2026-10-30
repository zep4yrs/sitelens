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
