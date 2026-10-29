package checks

// Match.Expr 运行时求值的回归断言（BUG-016 接线：afrog rule 级 expression
// 经 Match.Expr 在运行期判定）。判定语义与其它条件一致：任一条件不满足即
// 不命中；表达式编译失败/求值失败一律不命中（宁少报不误报）。

import (
	"strings"
	"testing"
)

func TestMatchBodyExpr(t *testing.T) {
	expr := `response.status == 200 && response.body.bcontains(b"EXPR-OK")`
	m := Match{Expr: expr}

	if !matchBody(m, 200, "xx EXPR-OK xx", nil, "h") {
		t.Errorf("表达式满足时应命中")
	}
	if matchBody(m, 404, "xx EXPR-OK xx", nil, "h") {
		t.Errorf("状态码不满足时不应命中")
	}
	if matchBody(m, 200, "nothing", nil, "h") {
		t.Errorf("正文不满足时不应命中")
	}
}

func TestMatchBodyExprWithStaticConditions(t *testing.T) {
	// 表达式与静态条件并存：全部满足才命中（AND 语义）。
	m := Match{
		StatusAny: []int{200},
		Contains:  []string{"static-word"},
		Expr:      `response.body.bcontains(b"expr-word")`,
	}
	if !matchBody(m, 200, "static-word expr-word", nil, "h") {
		t.Errorf("静态条件与表达式都满足时应命中")
	}
	if matchBody(m, 200, "static-word only", nil, "h") {
		t.Errorf("表达式不满足时不应命中")
	}
	if matchBody(m, 200, "expr-word only", nil, "h") {
		t.Errorf("静态条件不满足时不应命中")
	}
	if matchBody(m, 500, "static-word expr-word", nil, "h") {
		t.Errorf("状态码不满足时不应命中")
	}
}

func TestMatchBodyExprInvalidNeverHits(t *testing.T) {
	// 编译失败（含不支持原子）在运行期也一律不命中——不能因判不了就放行。
	m := Match{Expr: `oobCheck(oob.ProtocolDNS, 5)`}
	if matchBody(m, 200, "anything", nil, "h") {
		t.Errorf("不可判定的表达式不得命中")
	}
	m = Match{Expr: `response.body.bcontains(`}
	if matchBody(m, 200, "anything", nil, "h") {
		t.Errorf("语法错误表达式不得命中")
	}
}

func TestMatchBodyExprReason(t *testing.T) {
	// 命中原因要能解释（证据链自解释），不能只有一句"状态码命中"。
	m := Match{Expr: `response.body.bcontains(b"WHY-WORD")`}
	ok, why := matchBodyReason(m, 200, "WHY-WORD", nil, "h", nil)
	if !ok {
		t.Fatalf("应命中")
	}
	if why == "" || !strings.Contains(why, "afrog") {
		t.Errorf("命中原因应标注 afrog 表达式: %q", why)
	}
}
