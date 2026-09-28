package checks

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// priorTestServer check 路径返回 200 + 命中标记；其余路径（软 404 基线
// 探针）返回不同正文，避免全部被判成软 404。
func priorTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/c-") || strings.HasPrefix(r.URL.Path, "/wp-") {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("prior-test-marker"))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("no such page here"))
	}))
}

func priorTestList(ids ...string) []Check {
	list := make([]Check, 0, len(ids))
	for _, id := range ids {
		list = append(list, Check{ID: id, Lv: 1, Path: "/" + id,
			Match: Match{Status: 200, Contains: []string{"prior-test-marker"}},
			Title: id, Sev: "low"})
	}
	return list
}

func runOrder(t *testing.T, list []Check, prior *Prior) []string {
	t.Helper()
	srv := priorTestServer(t)
	defer srv.Close()
	_, runs := runList(httpx.New(0), srv.URL, list, 1, nil, nil, nil, prior)
	if len(runs) != len(list) {
		t.Fatalf("执行证据条数 %d != check 数 %d", len(runs), len(list))
	}
	out := make([]string, 0, len(runs))
	for _, r := range runs {
		out = append(out, r.Check)
		if !r.Hit {
			t.Fatalf("check %s 应命中（全标记服务器）", r.Check)
		}
	}
	return out
}

// TestPriorNilKeepsListOrder 回归护栏：无先验时严格清单序（4.0 语义），
// 先验通道不得改变默认行为。
func TestPriorNilKeepsListOrder(t *testing.T) {
	list := priorTestList("c-a", "c-b", "c-c")
	got := runOrder(t, list, nil)
	want := []string{"c-a", "c-b", "c-c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("无先验应保持清单序 %v，得到 %v", want, got)
		}
	}
}

// TestPriorBoostOrdering 前置通道：boost 把 c-d 提到队首，其余保持相对序。
func TestPriorBoostOrdering(t *testing.T) {
	list := priorTestList("c-a", "c-b", "c-c", "c-d")
	prior := &Prior{Boost: map[string]float64{"c-d": 0.9}}
	got := runOrder(t, list, prior)
	if got[0] != "c-d" {
		t.Fatalf("boost 的 c-d 应最先执行，得到 %v", got)
	}
	// 其余三条保持清单相对序
	rest := map[string]int{}
	for i, id := range got {
		rest[id] = i
	}
	if !(rest["c-a"] < rest["c-b"] && rest["c-b"] < rest["c-c"]) {
		t.Fatalf("未提权 check 应保持相对序，得到 %v", got)
	}
}

// TestFamilyBumpOnHit 中段通道：先执行的同家族命中（c-wp-readme）把
// 排在后面的姊妹 check（c-wp-login）拉到其余 check 之前。
func TestFamilyBumpOnHit(t *testing.T) {
	// 借用真实家族表：wp-readme / wp-login 同属 wp 家族
	list := priorTestList("wp-readme", "c-x", "c-y", "wp-login")
	prior := &Prior{Boost: map[string]float64{}}
	got := runOrder(t, list, prior)
	if got[0] != "wp-readme" {
		t.Fatalf("首个 check 应按清单序先执行，得到 %v", got)
	}
	if got[1] != "wp-login" {
		t.Fatalf("命中 wp 家族后姊妹 wp-login 应被联动提前，得到 %v", got)
	}
}

// TestFamilyBumpSingleShot 每家族至多联动一次：多条姊妹命中不叠加加分
// （第二个家族成员命中时家族已 bump，其余 check 顺序不受再次扰动）。
func TestFamilyBumpSingleShot(t *testing.T) {
	list := priorTestList("wp-readme", "wp-users", "c-x", "c-y")
	prior := &Prior{Boost: map[string]float64{}}
	got := runOrder(t, list, prior)
	// wp-readme 命中 → wp-users 提前；wp-users 命中不再重复 bump
	if got[0] != "wp-readme" || got[1] != "wp-users" {
		t.Fatalf("wp 家族姊妹应紧随首命中，得到 %v", got)
	}
}

// TestMLProductChecks 产品映射表：大小写包含匹配、无匹配返回 nil。
func TestMLProductChecks(t *testing.T) {
	if ids := MLProductChecks("wordpress/wordpress"); len(ids) == 0 {
		t.Fatal("wordpress 类应映射到 wp-* check")
	}
	if ids := MLProductChecks("Apache Tomcat"); len(ids) == 0 {
		t.Fatal("大小写不敏感匹配失败")
	}
	if ids := MLProductChecks("adobe/flash_player"); ids != nil {
		t.Fatalf("无映射产品应返回 nil，得到 %v", ids)
	}
	// php/php 与 phpmyadmin 都应落到 adminer
	if ids := MLProductChecks("phpmyadmin/phpmyadmin"); len(ids) == 0 || ids[0] != "adminer" {
		t.Fatalf("phpmyadmin 应映射到 adminer，得到 %v", ids)
	}
}

// TestIsExtended 扩展集判断：wp-readme 是 Lv1 扩展集。
func TestIsExtended(t *testing.T) {
	if !IsExtended("wp-readme") {
		t.Fatal("wp-readme 应为扩展集（Lv1）")
	}
	if IsExtended("phpinfo") {
		t.Fatal("phpinfo 应为核心集（Lv0）")
	}
	if IsExtended("no-such-check") {
		t.Fatal("未知 check 不应为扩展集")
	}
}
