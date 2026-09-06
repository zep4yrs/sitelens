package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

func TestActiveFPSpecMatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/druid/index.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>Druid Stat Index</title>body</html>`)
	})
	mux.HandleFunc("/adminer.php", func(w http.ResponseWriter, r *http.Request) {
		// body_contains 不满足（无 adminer 字样）→ 不命中
		fmt.Fprint(w, `<html>login page</html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rows := []intel.FingerDirRow{
		{Product: "Alibaba-Druid", Spec: intel.FingerDirMatchSpec{
			Paths:        []string{"/druid/index.html"},
			Status:       []int{200},
			BodyContains: []string{"druid"},
		}},
		{Product: "Adminer", Spec: intel.FingerDirMatchSpec{
			Paths:        []string{"/adminer.php"},
			Status:       []int{200},
			BodyContains: []string{"Adminer"},
		}},
		{Product: "NotFound-Product", Spec: intel.FingerDirMatchSpec{
			Paths:  []string{"/definitely-missing"},
			Status: []int{200},
		}},
	}
	hits := ActiveFP(client(), srv.URL, rows, nil, nil, 30)
	if len(hits) != 1 || hits[0].Product != "Alibaba-Druid" {
		t.Fatalf("应仅命中 Druid: %+v", hits)
	}
}

func TestActiveFPCapRequests(t *testing.T) {
	rows := make([]intel.FingerDirRow, 0, 10)
	for i := 0; i < 10; i++ {
		rows = append(rows, intel.FingerDirRow{
			Product: fmt.Sprintf("p%d", i),
			Spec:    intel.FingerDirMatchSpec{Paths: []string{fmt.Sprintf("/p%d", i)}},
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()

	hits := ActiveFP(client(), srv.URL, rows, nil, nil, 3)
	_ = hits // 上限 3 请求内完成，不 panic 即可
}
