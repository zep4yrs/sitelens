package intel

// C2-12 回归：年度 feed 的 meta sha256 校验。
//
// 契约：
//   - meta 声明的 sha256 与下载内容一致 → 正常写出；
//   - 不一致 → 拒绝该年数据，**整次更新不写出**（旧文件原样保留），
//     错误信息写明期望/实际摘要；
//   - meta 不可用（404/解析失败/无 sha256 字段）→ 保持旧行为（不校验）并 warn。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// feedTestSHA 返回 gz 字节的 sha256 小写十六进制。
func feedTestSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// setupFeedServers 注入 feed/meta URL，返回 server。
// metaFor(year) 返回 meta 响应体（空串表示 404）；feedFor(year) 返回 gz 字节（nil 表示 500）。
func setupFeedServers(t *testing.T,
	metaFor func(year string) string,
	feedFor func(year string) []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, ".meta"):
			year := path[strings.LastIndex(path, "-")+1 : len(path)-len(".meta")]
			meta := metaFor(year)
			if meta == "" {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(meta))
		case strings.HasSuffix(path, ".json.gz"):
			year := path[strings.LastIndex(path, "-")+1 : len(path)-len(".json.gz")]
			b := feedFor(year)
			if b == nil {
				w.WriteHeader(500)
				return
			}
			_, _ = w.Write(b)
		default:
			w.WriteHeader(404)
		}
	}))
	oldFeed, oldMeta := nvdFeedURL, nvdFeedMetaURL
	nvdFeedURL = srv.URL + "/nvdcve-2.0-%d.json.gz"
	nvdFeedMetaURL = srv.URL + "/nvdcve-2.0-%d.meta"
	t.Cleanup(func() {
		srv.Close()
		nvdFeedURL, nvdFeedMetaURL = oldFeed, oldMeta
	})
	return srv
}

// metaJSONFor 生成 NVD meta JSON 响应体。
func metaJSONFor(sha string) string {
	b, _ := json.Marshal(map[string]any{
		"lastModifiedDate": "2026-09-14T00:00:00Z",
		"sha256":           sha,
		"gzSize":           1,
		"size":             1,
	})
	return string(b)
}

func TestSyncNVDFeedDigestVerified(t *testing.T) {
	feed := gzBytes(t, `{"totalResults":1,"vulnerabilities":[`+nvdCVE1+`]}`)
	want := feedTestSHA(feed)
	setupFeedServers(t,
		func(string) string { return metaJSONFor(want) },
		func(string) []byte { return feed })

	out := filepath.Join(t.TempDir(), "feed.json.gz")
	if err := SyncNVDFeed(out, 2017, 2017, nil); err != nil {
		t.Fatalf("摘要校验通过时应成功: %v", err)
	}
	store, err := LoadNVD(out)
	if err != nil || store == nil || store.Len() != 1 {
		t.Fatalf("产物异常: store=%v err=%v", store, err)
	}
}

func TestSyncNVDFeedDigestMismatchKeepsOldData(t *testing.T) {
	// 旧镜像（合法 gz，内容为 OLD），校验失败后必须逐字节保持不变。
	oldEntries := []NVDEntry{{CVE: "CVE-1999-0001", Descr: "OLD-MIRROR"}}
	out := filepath.Join(t.TempDir(), "feed.json.gz")
	if err := writeNVDFile(out, oldEntries); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	feed := gzBytes(t, `{"totalResults":1,"vulnerabilities":[`+nvdCVE1+`]}`)
	wrong := strings.Repeat("0", 64) // 合法长度但错误的 sha256
	setupFeedServers(t,
		func(string) string { return metaJSONFor(wrong) },
		func(string) []byte { return feed })

	err = SyncNVDFeed(out, 2017, 2017, nil)
	if err == nil {
		t.Fatal("摘要不匹配应返回错误")
	}
	msg := err.Error()
	if !strings.Contains(msg, "摘要") {
		t.Errorf("错误应说明摘要校验失败: %v", err)
	}
	if !strings.Contains(msg, wrong) {
		t.Errorf("错误应写明 meta 期望摘要: %v", err)
	}
	if !strings.Contains(msg, feedTestSHA(feed)) {
		t.Errorf("错误应写明实际摘要: %v", err)
	}
	after, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatalf("旧数据文件不应被删除: %v", rerr)
	}
	if string(before) != string(after) {
		t.Fatal("摘要校验失败时不得覆盖旧数据文件")
	}
}

// TestSyncNVDFeedDigestMismatchMixedYearsRejectsAll 一年好一年坏：整次更新拒绝，
// 不得写出"只剩好年份"的半成品覆盖旧镜像。
func TestSyncNVDFeedDigestMismatchMixedYearsRejectsAll(t *testing.T) {
	goodFeed := gzBytes(t, `{"totalResults":1,"vulnerabilities":[`+nvdCVE1+`]}`)
	badFeed := gzBytes(t, `{"totalResults":1,"vulnerabilities":[`+nvdCVE1+`]}`)
	out := filepath.Join(t.TempDir(), "feed.json.gz")
	if err := writeNVDFile(out, []NVDEntry{{CVE: "CVE-1999-0002", Descr: "OLD"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(out)

	setupFeedServers(t,
		func(year string) string {
			if year == "2017" {
				return metaJSONFor(feedTestSHA(goodFeed))
			}
			return metaJSONFor(strings.Repeat("f", 64))
		},
		func(year string) []byte {
			if year == "2017" {
				return goodFeed
			}
			return badFeed
		})

	if err := SyncNVDFeed(out, 2017, 2018, nil); err == nil {
		t.Fatal("存在摘要不匹配的年份时应整体拒绝")
	}
	after, _ := os.ReadFile(out)
	if string(before) != string(after) {
		t.Fatal("存在摘要失败时不得写出半成品覆盖旧镜像")
	}
}

func TestSyncNVDFeedMetaUnavailableFallsBack(t *testing.T) {
	feed := gzBytes(t, `{"totalResults":1,"vulnerabilities":[`+nvdCVE1+`]}`)
	setupFeedServers(t,
		func(string) string { return "" }, // meta 404 → 保持旧行为
		func(string) []byte { return feed })

	out := filepath.Join(t.TempDir(), "feed.json.gz")
	if err := SyncNVDFeed(out, 2017, 2017, nil); err != nil {
		t.Fatalf("meta 不可用时应保持旧行为（不校验、不失败）: %v", err)
	}
	if store, _ := LoadNVD(out); store == nil || store.Len() != 1 {
		t.Fatalf("meta 不可用时数据仍应写出: %v", store)
	}
}

func TestParseFeedMeta(t *testing.T) {
	m, err := parseFeedMeta([]byte(`{"lastModifiedDate":"2026-01-01T00:00:00Z","sha256":"AB","gzSize":12,"size":34}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.SHA256 != "AB" || m.GzSize != 12 || m.Size != 34 ||
		feedYearOf([]byte(`{"lastModifiedDate":"2026-01-01T00:00:00Z"}`)) != "2026-01-01T00:00:00Z" {
		t.Fatalf("meta 解析异常: %+v", m)
	}
	if feedYearOf([]byte("not-json")) != "" {
		t.Fatal("非法 meta 应返回空字符串")
	}
}
