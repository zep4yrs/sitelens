// 数据热更新：mtime 惰性检查 + 重建 + 原子换枪。
//
// 覆盖四类数据：指纹库（technologies.json）、情报库（intel_dump +
// affected_ranges）、用户插件（plugins 目录）、Nuclei 模板库。
// 触发方式：每次扫描提交时自动惰性检查（stat 开销微秒级），
// 或 POST /api/admin/reload 强制刷新。重建完成后原子换入，
// 进行中的扫描持旧快照不受干扰。
package server

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"cnb.cool/feng-qiao/sitelens/internal/checks"
	"cnb.cool/feng-qiao/sitelens/internal/intel"
	"cnb.cool/feng-qiao/sitelens/internal/sitelens"
)

// dataPaths 参与热更新检查的数据文件（Nuclei 模板目录单独按 mtime 处理）。
func (s *Server) dataPaths() []string {
	cfg := s.cfg
	return []string{
		cfg.Intel.TechnologiesPath,
		cfg.Intel.DumpPath,
		cfg.Intel.RangesPath,
		cfg.Checks.PluginDir,
	}
}

// fileMTime 返回文件修改时间（unix 纳秒）；不存在返回 ok=false。
func fileMTime(path string) (int64, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return st.ModTime().UnixNano(), true
}

// dataChanged 任一数据文件的 mtime 相对基线发生变化（含新增/删除）。
func (s *Server) dataChanged() bool {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	for _, p := range s.dataPaths() {
		mt, _ := fileMTime(p)
		if s.lastData[p] != mt {
			return true
		}
	}
	return false
}

// markDataBaseline 把当前 mtime 记为新基线。
func (s *Server) markDataBaseline() {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	s.lastData = map[string]int64{}
	for _, p := range s.dataPaths() {
		if mt, ok := fileMTime(p); ok {
			s.lastData[p] = mt
		}
	}
}

// reloadData 重建指纹库与知识库并原子换入引擎（元数据统计同步刷新）。
// 单项加载失败保留旧数据继续服务。返回 (指纹条数, 情报条数)。
func (s *Server) reloadData() (techN, vulnN int) {
	if m, err := sitelens.LoadMatcher(s.cfg.Intel.TechnologiesPath); err == nil {
		s.matcher = m
		s.eng.SetMatcher(m)
		techN = m.Count()
	}
	if kb, err := intel.Load(s.cfg.Intel.DumpPath, s.cfg.Intel.RangesPath); err == nil {
		if entries, kerr := intel.LoadKEVExtra(
			filepath.Join(s.cfg.Store.DataDir, "kev_extra.json")); kerr == nil {
			kb.MergeKEV(entries)
		}
		s.kb.Store(kb)
		s.eng.SetKB(kb)
		if n, ok := kb.Stats()["vulns"].(int); ok {
			vulnN = n
		}
	}
	if m, err := loadTechMeta(s.cfg); err == nil {
		s.techIDs, s.techCnt = m.cats, m.count
	}
	s.checksReload()
	s.markDataBaseline()
	return techN, vulnN
}

// hAdminReload 手动强制热更新（受 X-Token 保护）。
func (s *Server) hAdminReload(w http.ResponseWriter, r *http.Request) {
	techN, vulnN := s.reloadData()
	s.checksReload()
	writeJSON(w, 200, map[string]any{
		"reloaded":     true,
		"technologies": techN,
		"vulns":        vulnN,
	})
}

// reloadIfDataChanged 惰性热更新：数据文件 mtime 有变化才重建（stat 微秒级）。
func (s *Server) reloadIfDataChanged() {
	if s.dataChanged() {
		log.Printf("检测到数据文件更新，重载指纹库/知识库/插件…")
		s.reloadData()
	}
}

// checksReload 用户插件目录变化时重新加载（mtime 门控在 checks 内部）。
func (s *Server) checksReload() { checks.ConfigurePlugins(s.cfg.Checks.PluginDir) }
