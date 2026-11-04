// Package seedrefresh 实现桌面版的「覆盖更新」：随包只读种子按包版本
// 合并进用户数据区。
//
// 背景（桌面壳历史行为）：首次启动把安装包内置的可变情报种子（NVD 字典、
// 模板情报行、指纹规则）**按「用户区不存在才拷」**刷进 %APPDATA%。这保证
// 了 update-* 的成果不会被升级覆盖，代价是**包内置种子永远进不来**：
// 用户没手动跑过 update-nvd 时，升级到带更新 NVD 快照的新版本，用户区里
// 那份旧快照仍是权威源——升了版本，情报还是旧的。
//
// 本包把「种子交付」从「存在即跳过」改成**按版本收敛**：
//   - 每次启动读用户区 data/.seed-manifest.json 里的交付版本；
//   - 与当前包版本（server.Version）相同 → 不动（一次交付只做一遍）；
//   - 不同 → 用包内置种子覆盖用户区副本。
//
// 不伤用户成果的边界写在 covered 白名单里：只覆盖「由包交付、且 update-*
// 会整体重建同一文件」的只读种子。字典词表、用户插件、模板池、扫描历史
// 一律不碰（不在白名单内 → 永不覆盖）。
package seedrefresh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ManifestName 交付版本清单文件名（落在用户数据目录根）。
const ManifestName = ".seed-manifest.json"

// Manifest 记录一次种子交付所属的包版本与文件摘要（可复核：从摘要能判断
// 用户区里那份是否就是本次包内的种子，而不是被 update-* 重写过的）。
type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"` // 相对用户数据目录的路径 → sha256
}

// DataDirName 用户数据区里承载种子的子目录名（与安装目录布局一致：
// 包内种子位于 <engine>/data，落到用户区即 <userData>/data）。
// 白名单按「包含 data/ 前缀的完整相对路径」书写，便于与配置里的
// intel.nvd_path 等键逐条对照。
const DataDirName = "data"

// covered 覆盖白名单：由包交付且 update-* 会整体重建的只读种子。
//   - data/*.json / *.json.gz：情报快照（NVD / 模板情报 / CVE 库 / 区间）
//   - data/go/**：指纹规则与技术库（update-fp / update-ehole 整体重生成）
//   - data/onnxruntime/**：推理运行时（随包分发，update-* 不产出）
//
// 明确**不在**白名单（用户成果，永不覆盖）：state/（扫描历史）、
// pools/nuclei（模板池，用户按需拉取）、plugins（用户插件）、
// data/wordlists（字典，用户可能自己加词）、data/asset-extras。
func covered(rel string) bool {
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return false
	}
	if strings.HasPrefix(rel, "data/wordlists/") || strings.HasPrefix(rel, "data/asset-extras/") {
		return false
	}
	if strings.HasPrefix(rel, "data/go/") || strings.HasPrefix(rel, "data/onnxruntime/") {
		return true
	}
	if strings.HasPrefix(rel, "data/") && strings.Count(rel, "/") == 1 {
		return true // data 根下的单层文件（各情报快照）
	}
	return false
}

// Plan 一次交付计划：要覆盖的文件、跳过/复用的文件。
type Plan struct {
	Version string
	Copy    []Item
	Keep    []Item
	// Unchanged 白名单内但「包内内容 == 用户区现有内容」的文件（C-16 差分：
	// 不再整份重拷，升级时只写真正变化的大资产，如 NVD 32MB / onnxruntime）。
	Unchanged []Item
	Skipped   bool // 版本一致，无需交付
}

// Item 单个种子文件（相对路径 + 源/目标绝对路径 + 是否已存在）。
type Item struct {
	Rel      string
	Src      string
	Dst      string
	Existing bool
	// Sha256 源文件摘要（Build 计算；Copy/Unchanged 均填充，供清单复用）。
	Sha256 string
}

// Build 比较包种子目录（seedDir，即安装目录里的 data 目录）与用户数据区
// （userDir），产出交付计划。installedVersion 为用户区已交付的版本
// （空表示从未交付）。
//
// C-16：白名单内文件做 sha256 差分——包内内容与用户区现有内容一致时归入
// Unchanged（不拷贝），仅 Copy 真正变化的文件。语义保持"包内快照是权威源"：
// 用户手动 update-* 改过的大资产（dst 摘要 != 包内摘要）仍会被覆盖。
func Build(seedDir, userDir, currentVersion, installedVersion string) (Plan, error) {
	p := Plan{Version: currentVersion}
	if currentVersion != "" && installedVersion == currentVersion {
		p.Skipped = true
		return p, nil
	}
	err := filepath.Walk(seedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(seedDir, path)
		if rerr != nil {
			return rerr
		}
		// seedDir 是「包内 data 目录」本身，目标一律挂到 <userData>/data 下
		// （与桌面壳既有 managed 键 intel.nvd_path=<userData>/data/... 同点位）。
		rel = filepath.Join(DataDirName, rel)
		dst := filepath.Join(userDir, rel)
		item := Item{Rel: filepath.ToSlash(rel), Src: path, Dst: dst}
		if _, serr := os.Stat(dst); serr == nil {
			item.Existing = true
		}
		if !covered(rel) {
			p.Keep = append(p.Keep, item)
			return nil
		}
		srcSum, herr := SHA256File(path)
		if herr != nil {
			return fmt.Errorf("计算种子摘要 %s：%w", item.Rel, herr)
		}
		item.Sha256 = srcSum
		if item.Existing {
			if dstSum, derr := SHA256File(dst); derr == nil && dstSum == srcSum {
				p.Unchanged = append(p.Unchanged, item) // 摘要一致：跳过拷贝
				return nil
			}
		}
		p.Copy = append(p.Copy, item)
		return nil
	})
	if err != nil {
		return p, err
	}
	return p, nil
}

// Apply 执行交付：只覆盖计划内的变化文件（原子替换：临时文件 + rename），
// 写回版本清单。即使没有文件需要拷贝也写清单——「这次包的种子已交付」这一点
// 必须落盘，否则下次启动会把同一批种子再覆盖一遍。
func Apply(plan Plan, userDir string) (int, error) {
	n := 0
	for _, it := range plan.Copy {
		if err := CopyFile(it.Src, it.Dst); err != nil {
			return n, fmt.Errorf("覆盖 %s：%w", it.Rel, err)
		}
		n++
	}
	if err := writeManifest(userDir, plan); err != nil {
		return n, err
	}
	return n, nil
}

// CopyFile 原子拷贝（同目录临时文件 + fsync + rename），失败不留半截文件。
func CopyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".seedtmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	// C-16：rename 前 fsync，避免"清单已记新版本、文件内容还在页缓存"的
	// 崩溃窗口（桌面壳升级后立刻断电的典型场景）。
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// writeManifest 落交付清单（含每份种子的 sha256，供复核与后续差分交付复用）。
//
// C-16：temp + fsync + rename 原子替换（原实现直接 WriteFile，崩溃会留下
// 半截 JSON → LoadManifest 视为"从未交付" → 下次启动整批重拷）。
// 清单覆盖本次计划内**全部白名单文件**（Copy + Unchanged），差分才有完整基线。
func writeManifest(userDir string, plan Plan) error {
	m := Manifest{Version: plan.Version, Files: map[string]string{}}
	for _, it := range append(append([]Item(nil), plan.Copy...), plan.Unchanged...) {
		sum := it.Sha256
		if sum == "" {
			var err error
			if sum, err = SHA256File(it.Dst); err != nil {
				return err
			}
		}
		m.Files[it.Rel] = sum
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(userDir, ManifestName+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功后 rename 已移走，失败则清理残留
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(userDir, ManifestName)); err != nil {
		return err
	}
	return nil
}

// LoadManifest 读用户区交付清单；不存在/损坏返回零值（视为从未交付）。
func LoadManifest(userDir string) Manifest {
	m := Manifest{}
	b, err := os.ReadFile(filepath.Join(userDir, ManifestName))
	if err != nil {
		return m
	}
	if json.Unmarshal(b, &m) != nil {
		return Manifest{}
	}
	return m
}

// SHA256File 计算文件摘要。
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Describe 给出一行人类可读的交付结论（壳/CLI 输出用）。
func (p Plan) Describe() string {
	if p.Skipped {
		return "种子已是 v" + p.Version + "，无需交付"
	}
	return fmt.Sprintf("种子交付 v%s：覆盖 %d 份，摘要一致复用 %d 份，保留用户区独有 %d 份",
		p.Version, len(p.Copy), len(p.Unchanged), len(p.Keep))
}
