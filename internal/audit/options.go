// RunOptions AU-02/AU-03 审计附加能力（additive）。
//
// 零值 = 与旧行为完全一致：Run(root,cfg,...) 与 --sarif 单独使用时输出不变。
package audit

import (
	"encoding/json"
	"fmt"
	"os"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// RunOptions 审计附加选项（全部可选；零值不改变既有行为）。
type RunOptions struct {
	// BaselinePath 只报「不在基线内」的新增发现（结果写 Report.BaselineIgnored）。
	BaselinePath string
	// UpdateBaselinePath 审计完成后把本轮全部发现指纹写入该基线文件。
	UpdateBaselinePath string
	// DiffPath 与上一次审计 JSON 报告按指纹对比，结果写 Report.Diff。
	DiffPath string
	// SCA 解析依赖清单（go.mod/package-lock.json/requirements.txt）并写 Report.SCA。
	SCA bool
}

// RunWithOptions 带附加选项的审计（基线/diff/SCA）。
// 既有 Run 行为不变（等价于 RunOptions{}）。
func RunWithOptions(root string, cfg config.AuditConfig, opts RunOptions,
	onProgress func(done, total int, msg string)) (*Report, error) {
	return run(root, cfg, opts, onProgress, nil)
}

// applyRunOptions 在审计主流程收尾后执行附加处理。
// 顺序：SCA（独立数据）→ 写基线（本轮全部发现）→ 基线过滤 → diff（过滤后）。
func applyRunOptions(rep *Report, root string, opts RunOptions) error {
	if opts.SCA {
		rep.SCA = ScanDependencies(scaRoot(root))
	}
	// 先写基线：写入的是本轮「全部」发现（过滤前），保证基线可累积复核。
	if opts.UpdateBaselinePath != "" {
		b := NewBaseline(rep)
		if err := b.Save(opts.UpdateBaselinePath); err != nil {
			return fmt.Errorf("写基线失败：%w", err)
		}
	}
	// 再按基线过滤：只报新增（含换代/行号漂移后的新告警）。
	if opts.BaselinePath != "" {
		b, err := LoadBaseline(opts.BaselinePath)
		if err != nil {
			return fmt.Errorf("读基线失败：%w", err)
		}
		ignored := ApplyBaseline(rep, b)
		rep.BaselineIgnored = &ignored
	}
	// diff 在基线过滤后的结果上做：new = 新增且不在基线的告警。
	if opts.DiffPath != "" {
		old, err := LoadReportFile(opts.DiffPath)
		if err != nil {
			return fmt.Errorf("读对比报告失败：%w", err)
		}
		rep.Diff = DiffReports(rep, old)
	}
	return nil
}

// LoadReportFile 读取既往审计 JSON 报告（--diff 输入）。
func LoadReportFile(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}
