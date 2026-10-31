// AU-02 回归：规则扩展（Java/Go/TS 各 ≥6 + OWASP 映射）、密钥前缀、
// 高熵检测、tsx/jsx 归一、SARIF properties.owasp。
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// 拼接构造假密钥：避免测试源码本身出现完整凭据字面量（被当作真实泄露）。
var (
	fakeJavaSecret = "hardcoded" + "pass123"
	fakeGoSecret   = "go-secret" + "123456"
	fakeTSSecret   = "fakekey" + "0123456789abcdef"
	fakeAWSKey     = "AKIA" + "1234567890ABCDEF"
	fakeGCPKey     = "AIza" + "1234567890abcdefghijklmnopqrstuvwxy"
	fakeGHTS       = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	fakeSlack      = "xoxb-" + "1234567890-abcdefghij"
	fakeAzureKey   = "AccountKey=" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
	fakeEntropy    = "V7kQ2mZ9xP4rT8wL1nB6"
)

func writeAuditFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRuleCoverageByLanguage AU-02 验收：Java/Go/TS 各 ≥6 条规则，且全部带
// OWASP 映射（rule.OWASP 非空、已登记 ruleOWASP）。
func TestRuleCoverageByLanguage(t *testing.T) {
	byLang := map[string]int{}
	for _, r := range auditRules {
		byLang[r.Lang]++
		if r.OWASP == "" {
			t.Errorf("规则 %s 缺 OWASP 映射", r.ID)
		}
		if want := ruleOWASP[r.ID]; want != r.OWASP {
			t.Errorf("规则 %s OWASP=%q，映射表=%q", r.ID, r.OWASP, want)
		}
	}
	for _, lang := range []string{"java", "go", "ts"} {
		if byLang[lang] < 6 {
			t.Fatalf("%s 规则数 %d，需 ≥6", lang, byLang[lang])
		}
	}
}

// TestJavaRulesHit Java 高频规则命中。
func TestJavaRulesHit(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "Login.java", `
class Login {
  void a() {
    String q = "SELECT * FROM u WHERE id=" + id;
    stmt.executeQuery("SELECT * FROM u WHERE id=" + id);
  }
  void b() { new ObjectInputStream(in).readObject(); }
  void c() { Runtime.getRuntime().exec(cmd); }
  void d() { Random r = new Random(); }
  void e() { String password = "`+fakeJavaSecret+`"; }
  void f() { resp.getWriter().print(data); }
  void g() { new File(request.getParameter("f")); }
}`)
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := hitRules(rep)
	for _, want := range []string{"JAVA-SQLI", "JAVA-DESER", "JAVA-CMD",
		"JAVA-WEAKRAND", "JAVA-SECRET", "JAVA-XSS", "JAVA-PATH"} {
		if !rules[want] {
			t.Errorf("Java 规则 %s 未命中", want)
		}
	}
}

// TestGoRulesHit Go 高频规则命中。
func TestGoRulesHit(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "main.go", `package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"html/template"
	"math/rand"
	"crypto/tls"
	"os/exec"
)

func main() {
	exec.Command("sh", "-c", cmd)
	db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id))
	_ = rand.Intn(10)
	password := "`+fakeGoSecret+`"
	_ = tls.Config{InsecureSkipVerify: true}
	_ = md5.New()
	_ = template.HTML(userInput)
	_ = sql.ErrNoRows
}`)
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := hitRules(rep)
	for _, want := range []string{"GO-CMD", "GO-SQLI", "GO-WEAKRAND", "GO-SECRET",
		"GO-TLS", "GO-HASH", "GO-TEMPLATE"} {
		if !rules[want] {
			t.Errorf("Go 规则 %s 未命中", want)
		}
	}
}

// TestTSRulesHit TypeScript 高频规则命中（.ts）。
func TestTSRulesHit(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "login.ts", `
function run(req: any, res: any, db: any, el: any, dir: string) {
  eval(userInput);
  el.innerHTML = html;
  db.query(`+"`"+`SELECT * FROM u WHERE id=${id}`+"`"+`);
  exec(`+"`"+`ls ${dir}`+"`"+`);
  Math.random();
  const api_key = "`+fakeTSSecret+`";
  jwt.sign(payload, "short");
  res.redirect(req.query.next);
}`)
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := hitRules(rep)
	for _, want := range []string{"TS-EVAL", "TS-INNERHTML", "TS-SQLI", "TS-CMD",
		"TS-WEAKRAND", "TS-SECRET", "TS-JWT", "TS-REDIRECT"} {
		if !rules[want] {
			t.Errorf("TS 规则 %s 未命中", want)
		}
	}
}

// TestTSXNormalized tsx 归一到 ts：TS 规则必须覆盖 .tsx（React 组件）。
func TestTSXNormalized(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "App.tsx", `export const App = () => { eval(x); return null; };`)
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hitRules(rep)["TS-EVAL"] {
		t.Fatalf(".tsx 应命中 TS-EVAL: %+v", rep.Findings)
	}
}

// TestSecretPrefixRules 云厂商/代码托管/IM token 前缀检测。
func TestSecretPrefixRules(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "secrets.env", strings.Join([]string{
		"AWS_ACCESS_KEY_ID=" + fakeAWSKey,
		"GCP_KEY=" + fakeGCPKey,
		"GITHUB_TOKEN=" + fakeGHTS,
		"SLACK_TOKEN=" + fakeSlack,
		"AZURE_CONN=DefaultEndpointsProtocol=https;" + fakeAzureKey + "===",
	}, "\n"))
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules := hitRules(rep)
	for _, want := range []string{"GEN-AWSKEY", "GEN-GCPKEY", "GEN-GITHUBTOKEN",
		"GEN-SLACKTOKEN", "GEN-AZUREKEY"} {
		if !rules[want] {
			t.Errorf("密钥前缀规则 %s 未命中", want)
		}
	}
}

// TestEntropyDetection 高熵字面量命中 GEN-ENTROPY；低熵/占位符不命中，
// 且 Match/Snippet 不出现密钥值（避免报告二次泄露）。
func TestEntropyDetection(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "conf.py", "api_key = \""+fakeEntropy+"\"\n")
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ent *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Rule == "GEN-ENTROPY" {
			ent = &rep.Findings[i]
		}
	}
	if ent == nil {
		t.Fatalf("高熵字面量应命中 GEN-ENTROPY: %+v", rep.Findings)
	}
	if strings.Contains(ent.Snippet, fakeEntropy) || strings.Contains(ent.Match, fakeEntropy) {
		t.Fatalf("熵命中不得把密钥值写入报告: snippet=%q match=%q", ent.Snippet, ent.Match)
	}
	if ent.OWASP == "" {
		t.Error("GEN-ENTROPY 应带 OWASP 映射")
	}

	// 低熵/占位符：不报 GEN-ENTROPY
	dir2 := t.TempDir()
	writeAuditFile(t, dir2, "conf2.py",
		"secret = \"aaaaaaaaaaaaaaaaaaaa\"\ntoken = \"your_token_here_example\"\n")
	rep2, err := Run(dir2, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hitRules(rep2)["GEN-ENTROPY"] {
		t.Fatalf("低熵/占位符不应命中 GEN-ENTROPY: %+v", rep2.Findings)
	}
}

// TestOWASPPropagation Finding.owasp 输出 + SARIF rules[].properties.owasp。
func TestOWASPPropagation(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "x.py", "eval(x)\n")
	rep, err := Run(dir, config.AuditConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 || rep.Findings[0].OWASP == "" {
		t.Fatalf("Finding 应带 owasp: %+v", rep.Findings)
	}
	// JSON 可输出（omitempty 之外有值）
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"owasp"`) {
		t.Fatalf("JSON 报告应含 owasp 字段: %s", data)
	}
	// SARIF：规则 properties.owasp 存在
	sarifData, err := ToSARIF(rep, "test")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string            `json:"id"`
						Properties map[string]string `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifData, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		if r.ID == "PY-EVAL" {
			found = r.Properties["owasp"] == owaspInjection
		}
	}
	if !found {
		t.Fatalf("SARIF 规则应带 properties.owasp: %s", sarifData)
	}
}

// hitRules 命中的规则 id 集合。
func hitRules(rep *Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range rep.Findings {
		out[f.Rule] = true
	}
	return out
}
