// AU-03 SCA（软件成分分析）依赖清单解析。
//
// 解析审计目录内的三类依赖清单：
//   - go.mod                （Go 模块，require 单行/块语法）
//   - package-lock.json     （npm v1 dependencies / v2+ packages）
//   - requirements*.txt     （PyPI，只认 name==version 精确版本）
//
// 漏洞查询：**只有存在本地 OSV 库时才查**。库路径优先取环境变量
// SITLENS_OSV_DB，其次仓库内约定路径 data/osv_db.json / data/state/osv_db.json。
// 库不存在（当前仓库即如此：没有 internal/osv 包、也没有 osv-sync 落盘的
// 包→漏洞库）时，报告 status="unknown"，只输出依赖清单并明确标注漏洞状态
// 未知——不联网、不臆造漏洞。本地库格式（最小 JSON）：
//
//	{"vulns":[{"id":"GHSA-xxxx","summary":"...","severity":"high",
//	           "ecosystem":"Go","package":"golang.org/x/text",
//	           "affected":">=0.3.0,<0.3.8"}]}
//
// affected 为空 = 该系统/包的所有版本受影响；否则复用 versioncmp.VersionIn
// 的区间语法（>=x,<y / <=x / =x 等）。
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/versioncmp"
)

const (
	scaMaxManifests = 50   // 单次审计最多解析的清单文件数
	scaMaxDeps      = 5000 // 依赖条目上限（防超大锁文件拖垮报告）
	// scaOSVDBEnv 本地 OSV 库路径环境变量（显式指定优先）。
	scaOSVDBEnv = "SITLENS_OSV_DB"
)

// scaOSVDBDefaults 仓库内约定本地 OSV 库候选路径（相对进程 CWD）。
var scaOSVDBDefaults = []string{
	filepath.Join("data", "osv_db.json"),
	filepath.Join("data", "state", "osv_db.json"),
}

// SCAVuln 一条依赖漏洞（来自本地 OSV 库）。
type SCAVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary,omitempty"`
	Severity string `json:"severity,omitempty"`
	Affected string `json:"affected,omitempty"`
}

// SCADependency 一条依赖（跨清单去重后）。
type SCADependency struct {
	Ecosystem string    `json:"ecosystem"` // Go | npm | PyPI
	Name      string    `json:"name"`
	Version   string    `json:"version,omitempty"` // 精确版本；空 = 无法比对
	Spec      string    `json:"spec,omitempty"`    // 原始约束（requirements 非 == 时）
	Direct    bool      `json:"direct,omitempty"`  // go.mod 直接依赖（无 // indirect）
	Sources   []string  `json:"sources,omitempty"` // 相对路径清单文件
	Status    string    `json:"status"`            // checked | unknown
	Vulns     []SCAVuln `json:"vulns,omitempty"`
}

// SCAReport SCA 结果（挂到 Report.SCA，additive）。
type SCAReport struct {
	Status       string          `json:"status"` // queried（有本地 OSV 库）| unknown
	Note         string          `json:"note,omitempty"`
	OSVSource    string          `json:"osv_source,omitempty"`
	Files        []string        `json:"files,omitempty"`
	Total        int             `json:"total"`
	Vulnerable   int             `json:"vulnerable,omitempty"`
	ByEcosystem  map[string]int  `json:"by_ecosystem,omitempty"`
	Dependencies []SCADependency `json:"dependencies,omitempty"`
}

// osvDB 本地 OSV 库最小结构。
type osvDB struct {
	Vulns []osvRecord `json:"vulns"`
}

type osvRecord struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Affected  string `json:"affected"`
}

// scaRoot 单文件审计时以所在目录为清单发现根（目录审计用根本身）。
func scaRoot(root string) string {
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return filepath.Dir(root)
	}
	return root
}

// ScanDependencies 扫描 root 内依赖清单；有本地 OSV 库时标注漏洞，
// 否则 status=unknown（只输出清单，不产生漏洞结论）。永不返回 error：
// 清单解析失败记入 Note，审计主流程不被 SCA 拖垮。
func ScanDependencies(root string) *SCAReport {
	rep := &SCAReport{ByEcosystem: map[string]int{}}
	manifests := findManifests(root)
	if len(manifests) == 0 {
		rep.Status = "unknown"
		rep.Note = "未发现 go.mod / package-lock.json / requirements*.txt；无依赖可分析"
		return rep
	}
	var deps []SCADependency
	var parseErrs []string
	for _, mf := range manifests {
		data, err := os.ReadFile(mf.abs)
		if err != nil {
			parseErrs = append(parseErrs, mf.rel+": 读取失败")
			continue
		}
		switch mf.kind {
		case "gomod":
			deps = append(deps, parseGoMod(data, mf.rel)...)
		case "npmlock":
			got, perr := parsePackageLock(data, mf.rel)
			if perr != nil {
				parseErrs = append(parseErrs, mf.rel+": "+perr.Error())
				continue
			}
			deps = append(deps, got...)
		case "requirements":
			deps = append(deps, parseRequirements(data, mf.rel)...)
		}
		rep.Files = append(rep.Files, mf.rel)
	}
	deps = mergeDeps(deps)
	if len(deps) > scaMaxDeps {
		deps = deps[:scaMaxDeps]
		parseErrs = append(parseErrs, fmt.Sprintf("依赖超过上限 %d，已截断", scaMaxDeps))
	}

	db, dbPath := loadLocalOSVDB()
	if db == nil {
		rep.Status = "unknown"
		rep.Note = "未发现本地 OSV 库（可设 " + scaOSVDBEnv +
			" 指向 JSON 漏洞库）；依赖清单已输出，漏洞状态 unknown"
	} else {
		rep.Status = "queried"
		rep.OSVSource = dbPath
	}
	if len(parseErrs) > 0 {
		if rep.Note != "" {
			rep.Note += "；"
		}
		rep.Note += strings.Join(parseErrs, "；")
	}

	for i := range deps {
		d := &deps[i]
		rep.ByEcosystem[d.Ecosystem]++
		if db == nil || d.Version == "" {
			d.Status = "unknown" // 无库/无精确版本：状态未知，不臆造
			continue
		}
		d.Status = "checked"
		for _, rec := range db.Vulns {
			if !scaSamePackage(rec, *d) {
				continue
			}
			if rec.Affected != "" && !versioncmp.VersionIn(d.Version, rec.Affected) {
				continue
			}
			d.Vulns = append(d.Vulns, SCAVuln{
				ID: rec.ID, Summary: rec.Summary,
				Severity: rec.Severity, Affected: rec.Affected,
			})
		}
		if len(d.Vulns) > 0 {
			sort.Slice(d.Vulns, func(a, b int) bool { return d.Vulns[a].ID < d.Vulns[b].ID })
			rep.Vulnerable++
		}
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	sort.Strings(rep.Files)
	rep.Dependencies = deps
	rep.Total = len(deps)
	return rep
}

// scaSamePackage 依赖与本地库记录是否同一生态+包名。
func scaSamePackage(rec osvRecord, d SCADependency) bool {
	if rec.ID == "" || rec.Package == "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(rec.Ecosystem), d.Ecosystem) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(rec.Package), d.Name)
}

// scaManifest 一个待解析清单。
type scaManifest struct {
	abs  string
	rel  string
	kind string // gomod | npmlock | requirements
}

// findManifests 遍历 root 收集依赖清单（跳过 vendor/node_modules 等目录）。
func findManifests(root string) []scaManifest {
	var out []scaManifest
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if err == nil && d.IsDir() && p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if len(out) >= scaMaxManifests {
			return filepath.SkipAll
		}
		base := strings.ToLower(d.Name())
		kind := ""
		switch {
		case base == "go.mod":
			kind = "gomod"
		case base == "package-lock.json":
			kind = "npmlock"
		case base == "requirements.txt" ||
			(strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")):
			kind = "requirements"
		}
		if kind == "" {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		out = append(out, scaManifest{abs: p, rel: filepath.ToSlash(rel), kind: kind})
		return nil
	})
	return out
}

// parseGoMod 解析 go.mod 的 require（单行与块语法），标记 // indirect。
func parseGoMod(data []byte, source string) []SCADependency {
	var out []SCADependency
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		raw := line
		t := strings.TrimSpace(raw)
		if i := strings.Index(t, "//"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" {
			continue
		}
		if !inBlock && t == "require (" {
			inBlock = true
			continue
		}
		if inBlock && t == ")" {
			inBlock = false
			continue
		}
		fields := strings.Fields(t)
		if !inBlock {
			if len(fields) < 3 || fields[0] != "require" {
				continue
			}
			fields = fields[1:]
		}
		if len(fields) < 2 {
			continue
		}
		name, ver := fields[0], fields[1]
		out = append(out, SCADependency{
			Ecosystem: "Go", Name: name, Version: ver,
			Direct:  !strings.Contains(raw, "// indirect"),
			Sources: []string{source},
		})
	}
	return out
}

// parsePackageLock 解析 npm package-lock.json（v1 dependencies / v2+ packages）。
func parsePackageLock(data []byte, source string) ([]SCADependency, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("package-lock.json 解析失败")
	}
	out := make([]SCADependency, 0, len(lock.Packages)+len(lock.Dependencies))
	for key, pkg := range lock.Packages {
		if key == "" { // 根包（被审计项目自身）不计入依赖
			continue
		}
		name := npmNameFromPath(key)
		if name == "" || pkg.Version == "" {
			continue
		}
		out = append(out, SCADependency{
			Ecosystem: "npm", Name: name, Version: pkg.Version,
			Sources: []string{source},
		})
	}
	for name, dep := range lock.Dependencies {
		if name == "" || dep.Version == "" {
			continue
		}
		// v1 结构无 packages 时才有意义；v2+ 两者并存会由 mergeDeps 去重。
		out = append(out, SCADependency{
			Ecosystem: "npm", Name: name, Version: dep.Version,
			Sources: []string{source},
		})
	}
	return out, nil
}

// npmNameFromPath 从 packages 键取包名："node_modules/@scope/x" → "@scope/x"，
// "a/node_modules/b" → "b"；键不含 node_modules 返回空（根/workspace 条目）。
func npmNameFromPath(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}

// parseRequirements 解析 requirements*.txt：只认 name==version（精确版本）；
// 其它约束（>=、~=、无版本）记为 Spec 且 Version 空（漏洞状态 unknown）。
func parseRequirements(data []byte, source string) []SCADependency {
	var out []SCADependency
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
			continue
		}
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if i := strings.Index(t, ";"); i >= 0 { // 环境标记
			t = strings.TrimSpace(t[:i])
		}
		if t == "" {
			continue
		}
		if i := strings.Index(t, "=="); i > 0 {
			name := strings.TrimSpace(t[:i])
			ver := strings.TrimSpace(t[i+2:])
			// 去掉 extras：requests[security]==2.0
			if b := strings.IndexByte(name, '['); b > 0 {
				name = name[:b]
			}
			if name == "" || ver == "" {
				continue
			}
			out = append(out, SCADependency{
				Ecosystem: "PyPI", Name: name, Version: ver,
				Sources: []string{source},
			})
			continue
		}
		// 非精确约束：保留名称与原始约束，版本不可比对。
		name, spec := t, ""
		for _, op := range []string{">=", "<=", "~=", "!=", ">", "<", "==="} {
			if i := strings.Index(name, op); i > 0 {
				spec = strings.TrimSpace(name[i:])
				name = strings.TrimSpace(name[:i])
				break
			}
		}
		if b := strings.IndexByte(name, '['); b > 0 {
			name = name[:b]
		}
		if name == "" {
			continue
		}
		out = append(out, SCADependency{
			Ecosystem: "PyPI", Name: name, Spec: spec,
			Sources: []string{source},
		})
	}
	return out
}

// mergeDeps 按 ecosystem|name|version 去重并合并来源清单。
func mergeDeps(deps []SCADependency) []SCADependency {
	type key struct{ eco, name, ver, spec string }
	idx := map[key]int{}
	out := make([]SCADependency, 0, len(deps))
	for _, d := range deps {
		k := key{d.Ecosystem, strings.ToLower(d.Name), d.Version, d.Spec}
		if i, ok := idx[k]; ok {
			out[i].Sources = append(out[i].Sources, d.Sources...)
			out[i].Direct = out[i].Direct || d.Direct
			continue
		}
		idx[k] = len(out)
		out = append(out, d)
	}
	for i := range out {
		out[i].Sources = uniqueSorted(out[i].Sources)
	}
	return out
}

// uniqueSorted 去重排序（保持确定性输出）。
func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// loadLocalOSVDB 加载本地 OSV 库：环境变量优先，其次仓库约定候选。
// 返回 nil 表示无本地库可用（调用方标 unknown）。
func loadLocalOSVDB() (*osvDB, string) {
	if p := strings.TrimSpace(os.Getenv(scaOSVDBEnv)); p != "" {
		if db, err := readOSVDB(p); err == nil {
			return db, p
		}
		return nil, ""
	}
	for _, p := range scaOSVDBDefaults {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if db, err := readOSVDB(p); err == nil {
			return db, p
		}
	}
	return nil, ""
}

// readOSVDB 读取最小本地 OSV 库 JSON。vulns 字段必须存在（空数组 =
// 已查询但无已知漏洞，是合法库）；缺失字段视为格式错误，避免空对象被
// 当成「有库但零漏洞」而误报「已扫」。
func readOSVDB(path string) (*osvDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Vulns *[]osvRecord `json:"vulns"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Vulns == nil {
		return nil, fmt.Errorf("OSV 库缺 vulns 字段")
	}
	return &osvDB{Vulns: *raw.Vulns}, nil
}
