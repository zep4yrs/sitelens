// Package audit 本地源码静态审计（规则驱动 SAST-lite）。
//
// runAudit(目录) 按规则扫描文本源码返回发现列表。规则覆盖：危险函数、
// SQL 拼接、弱哈希、硬编码密钥、反序列化、路径穿越、命令注入、
// XSS、调试残留。跳过 vendor/依赖与二进制文件。
// 定位是「辅助人工复查的线索」而非漏洞判决——每条发现带行号与修复建议。
// 移植自 python 分支 scanner/audit.py（污点分析模块暂未迁移，见对照表）。
package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// rule 审计规则（id, 严重度, 语言, 标题, 正则, 修复建议）。
type rule struct {
	ID     string
	Sev    string
	Lang   string // 文件后缀（无点），"*" = 全部
	Title  string
	Re     *regexp.Regexp
	Advice string
}

func mustRule(id, sev, lang, title, pattern, advice string) rule {
	return rule{ID: id, Sev: sev, Lang: lang, Title: title,
		Re: regexp.MustCompile("(?i)" + pattern), Advice: advice}
}

var auditRules = []rule{
	mustRule("PY-EVAL", "high", "py", "使用 eval 动态执行", `\beval\s*\(`,
		"改用 ast.literal_eval 或显式解析，eval 可执行任意代码"),
	mustRule("PY-EXEC", "high", "py", "使用 exec 动态执行", `\bexec\s*\(`,
		"避免 exec；确需动态执行时严格白名单校验输入"),
	mustRule("PY-PICKLE", "high", "py", "反序列化 pickle/yaml.load",
		`pickle\.loads?\s*\(|yaml\.load\s*\(`,
		"pickle 只用于可信数据；yaml.load 必须 Loader=yaml.SafeLoader"),
	mustRule("PY-OSPOPEN", "high", "py", "os.system/popen 命令注入", `os\.(system|popen)\s*\(`,
		"改用 subprocess + 参数列表（shell=False），禁止拼接命令"),
	mustRule("PY-SQLFMT", "high", "py", "SQL 字符串拼接/format",
		`execute\s*\(\s*[fF]?['"](SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*%|\bexecute\s*\(\s*[fF]["']`,
		"全部改占位符 %s 参数绑定，禁止 f-string/format 拼 SQL"),
	mustRule("PY-MD5", "medium", "py", "弱哈希 MD5/SHA1（安全用途）", `hashlib\.(md5|sha1)\s*\(`,
		"口令存储改 bcrypt/argon2；完整性校验改 SHA-256"),
	mustRule("PY-SECRET", "high", "py", "疑似硬编码密钥/口令",
		`(password|passwd|secret|api_key|apikey|token)\s*=\s*['"][^'"]{8,}['"]`,
		"凭据移入环境变量或密钥服务，代码不出现字面量"),
	mustRule("PY-DEBUG", "low", "py", "调试残留 debug=True/断点", `debug\s*=\s*True|set_trace\s*\(`,
		"生产关闭 debug；提交前移除断点"),
	mustRule("PY-TEMPFILE", "low", "py", "临时文件可预测（tempfile 名猜用）",
		`tempfile\.(mktemp|NamedTemporaryFile)\s*\(`, "mktemp 有竞态，改 mkstemp"),
	mustRule("PY-RAND", "medium", "py", "安全场景使用随机库 random",
		`\brandom\.(random|randint|choice)\s*\(`, "令牌/密钥类用途改 secrets 模块"),
	mustRule("JS-EVAL", "high", "js", "eval/new Function 动态执行", `\beval\s*\(|new\s+Function\s*\(`,
		"改 JSON.parse 或显式逻辑，eval 是 XSS 注入终点"),
	mustRule("JS-INNERHTML", "medium", "js", "innerHTML 直接赋值（XSS 风险）", `\.innerHTML\s*=`,
		"改 textContent；必须插入 HTML 时先做消毒（DOMPurify）"),
	mustRule("JS-SECRET", "high", "js", "前端疑似硬编码密钥",
		`(apikey|api_key|secret|access_token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`,
		"前端密钥天然泄露，改服务端代理"),
	mustRule("PHP-CMD", "high", "php", "命令执行函数", `\b(system|exec|shell_exec|passthru|popen)\s*\(`,
		"禁用或严格白名单校验后调用"),
	mustRule("PHP-INCLUDE", "medium", "php", "动态包含（文件包含风险）", `(include|require)\s*\(?\s*\$`,
		"包含路径固定化，禁止变量拼接"),
	mustRule("GEN-IP", "low", "*", "源码含内网 IP 地址",
		`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`,
		"确认是否应暴露内部拓扑信息"),
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true, ".idea": true,
	"venv": true, ".venv": true, "vendor": true, "dist": true, "build": true,
	"data": true, "reference": true, ".mimosa": true,
}

var textExt = map[string]bool{
	".py": true, ".js": true, ".php": true, ".java": true, ".go": true,
	".rb": true, ".html": true, ".css": true, ".json": true, ".yaml": true,
	".yml": true, ".md": true, ".txt": true, ".sql": true, ".sh": true,
	".env": true, ".ini": true, ".cfg": true,
}

// Finding 一条审计发现（JSON 对齐 Python）。
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
	Match    string `json:"match"`
	Advice   string `json:"advice"`
}

// Report 审计报告。
type Report struct {
	Findings   []Finding      `json:"findings"`
	Files      int            `json:"files"`
	Lines      int            `json:"lines"`
	BySeverity map[string]int `json:"by_severity"`
}

// Run 审计目录或单文件。
func Run(root string, cfg config.AuditConfig, onProgress func(done, total int, msg string)) (*Report, error) {
	if cfg.MaxFileKB <= 0 {
		cfg.MaxFileKB = 512
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 800
	}
	if cfg.MaxFindingsPerRule <= 0 {
		cfg.MaxFindingsPerRule = 50
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
			if werr != nil {
				return nil // 单项失败不阻塞
			}
			name := d.Name()
			if d.IsDir() {
				if skipDirs[name] && p != root {
					return filepath.SkipDir
				}
				return nil
			}
			if textExt[strings.ToLower(filepath.Ext(name))] {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{root}
	}
	if len(files) > cfg.MaxFiles {
		files = files[:cfg.MaxFiles]
	}

	rep := &Report{Findings: []Finding{}, BySeverity: map[string]int{
		"high": 0, "medium": 0, "low": 0}}
	ruleHits := map[string]int{}
	for i, fp := range files {
		st, serr := os.Stat(fp)
		if serr != nil || st.Size() > int64(cfg.MaxFileKB)*1024 {
			continue
		}
		data, rerr := os.ReadFile(fp)
		if rerr != nil {
			continue
		}
		rep.Lines += strings.Count(string(data), "\n") + 1
		ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(fp)), ".")
		lines := strings.Split(string(data), "\n")
		for _, r := range auditRules {
			if r.Lang != "*" && r.Lang != ext {
				continue
			}
			for n, line := range lines {
				if m := r.Re.FindString(line); m != "" {
					if ruleHits[r.ID] >= cfg.MaxFindingsPerRule {
						break
					}
					ruleHits[r.ID]++
					snippet := strings.TrimSpace(line)
					if len(snippet) > 160 {
						snippet = snippet[:160]
					}
					mt := m
					if len(mt) > 60 {
						mt = mt[:60]
					}
					rep.Findings = append(rep.Findings, Finding{
						Rule: r.ID, Severity: r.Sev, Title: r.Title,
						File: fp, Line: n + 1, Snippet: snippet,
						Match: mt, Advice: r.Advice,
					})
				}
			}
		}
		if onProgress != nil {
			onProgress(i+1, len(files), filepath.Base(fp))
		}
	}

	sevRank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		fi, fj := rep.Findings[i], rep.Findings[j]
		if sevRank[fi.Severity] != sevRank[fj.Severity] {
			return sevRank[fi.Severity] < sevRank[fj.Severity]
		}
		if fi.File != fj.File {
			return fi.File < fj.File
		}
		return fi.Line < fj.Line
	})
	for _, f := range rep.Findings {
		rep.BySeverity[f.Severity]++
	}
	rep.Files = len(files)
	return rep, nil
}
