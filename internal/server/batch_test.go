package server

import "testing"

func TestParseBatchItems(t *testing.T) {
	req := batchRequest{
		URLs: []string{"https://a.example.com", "https://b.example.com quick", "https://c.example.com 完整", "   "},
		Entries: []batchItem{
			{URL: "https://d.example.com", Level: "deep"},
			{URL: "https://e.example.com", Level: "bogus"},
		},
	}
	got := parseBatchItems(req, 10)
	if len(got) != 5 {
		t.Fatalf("应解析 5 条有效目标，实得 %d: %+v", len(got), got)
	}
	want := []struct{ url, level string }{
		{"https://d.example.com", "deep"},
		{"https://e.example.com", ""}, // 非法档位清空
		{"https://a.example.com", ""},
		{"https://b.example.com", "quick"},
		{"https://c.example.com", "full"},
	}
	for i, w := range want {
		if got[i].URL != w.url || got[i].Level != w.level {
			t.Fatalf("第 %d 条错误：got %+v want %+v", i, got[i], w)
		}
	}
}

func TestParseBatchItemsCap(t *testing.T) {
	req := batchRequest{URLs: []string{"https://a.com", "https://b.com", "https://c.com"}}
	if got := parseBatchItems(req, 2); len(got) != 2 {
		t.Fatalf("应截断到上限 2，实得 %d", len(got))
	}
	if got := parseBatchItems(batchRequest{}, 10); len(got) != 0 {
		t.Fatalf("空请求应返回空列表，实得 %+v", got)
	}
}

func TestBatchHost(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/a":       "example.com",
		"http://127.0.0.1:8080/x":     "127.0.0.1",
		"not a url":                   "not a url",
		"https://sub.example.com:443": "sub.example.com",
	}
	for in, want := range cases {
		if got := batchHost(in); got != want {
			t.Fatalf("batchHost(%q)=%q want %q", in, got, want)
		}
	}
}
