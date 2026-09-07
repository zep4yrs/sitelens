package nuclei

import (
	"testing"
)

func TestCosine(t *testing.T) {
	a := termVec(tokenize("wordpress backup exposure"))
	b := termVec(tokenize("wordpress plugin backup leak"))
	c := termVec(tokenize("nginx server config"))

	sab := cosine(a, b)
	sac := cosine(a, c)
	if sab <= sac {
		t.Fatalf("词面更接近的相似度应更高: ab=%f ac=%f", sab, sac)
	}
	if cosine(a, map[string]float64{}) != 0 || cosine(map[string]float64{}, b) != 0 {
		t.Fatal("零向量相似度应为 0")
	}
	if sa := cosine(a, a); sa < 0.99 {
		t.Fatalf("自相似应接近 1: %f", sa)
	}
}

// 相关度路由（TF 余弦）应把词面更接近的模板排到 LRU 同层的前面。
func TestSelectCosineRelevance(t *testing.T) {
	entries := []Entry{
		{Path: "n-nginx-hardening.yaml", Name: "Nginx Hardening Check", Tags: []string{"nginx"}, Sev: "low"},
		{Path: "w-wp-backup.yaml", Name: "WordPress Backup Exposure", Tags: []string{"wordpress", "backup"}, Sev: "high"},
	}
	lastRun := map[string]int64{}
	sel := Select(entries, map[string]bool{}, "wordpress 备份泄露", 1, lastRun)
	if len(sel) != 1 || sel[0].Path != "w-wp-backup.yaml" {
		t.Fatalf("TF 余弦相关度排序失败: %+v", sel)
	}
}
