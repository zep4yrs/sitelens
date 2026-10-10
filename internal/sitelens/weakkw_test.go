package sitelens

import "testing"

// TestTokenizeKeyword：关键词分词（ASCII 字母数字段 / 连续非 ASCII 段）。
func TestTokenizeKeyword(t *testing.T) {
	cases := map[string][]string{
		"dvwa/css/login.css": {"dvwa", "css", "login", "css"},
		"Apache":             {"apache"},
		"must-revalidate":    {"must", "revalidate"},
		`type="password"`:    {"type", "password"},
		"登录":                 {"登录"},
		"管理中心":               {"管理中心"},
		"a.b":                {"a", "b"},
		"":                   nil,
		"---":                nil,
	}
	for in, want := range cases {
		got := tokenizeKeyword(in)
		if len(got) != len(want) {
			t.Errorf("tokenizeKeyword(%q) = %v，期望 %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("tokenizeKeyword(%q) = %v，期望 %v", in, got, want)
				break
			}
		}
	}
}

// TestWeakKeyword：区分度判定——全部 token 通用 = 弱；任一带非通用 token = 强。
//
// 该集合直接取自 DVWA 误判实测：前者当年把 54 个无关产品判为命中。
//
// 说明：Apache / PHP / Debian 等由 **header 通道**（server= / x-powered-by=）
// 命中，不依赖 html 关键词强弱，故不在下方 strong 集合内；它们的识别在
// fingerprint 的 headers 通道完成（那些通道不应用弱词过滤）。
func TestWeakKeyword(t *testing.T) {
	weak := []string{
		"login", "username", "password", "user", "application", "User",
		`type="password"`, "must-revalidate", "no-cache", "admin",
		"login.php", "login.css", "login_logo", "/login", "login.aspx",
		"登录", "管理", "系统", "管理中心", "后台",
		"", "---", "  ",
	}
	for _, s := range weak {
		if !weakKeyword(s) {
			t.Errorf("weakKeyword(%q) 应为弱证据（全部 token 通用）", s)
		}
	}
	strong := []string{
		"dvwa/css/login.css", // dvwa 非通用
		"dvwa/images/login_logo.png",
		"TOPSEC",            // 天融信产品串
		"Powered by Discuz", // discuz 非通用
		"wp-content",        // wordpress 特征
		"typecho", "joomla", "drupal",
		"<title>Damn Vulnerable Web App (DVWA) - Login</title>",
		"image/aaa.png", // aaa 非通用
	}
	for _, s := range strong {
		if weakKeyword(s) {
			t.Errorf("weakKeyword(%q) 应为强证据（存在非通用 token）", s)
		}
	}
}

// TestWeakKeywordRegressionDVWA 是**误判回归**：DVWA 实测页面的关键词集合，
// 修复前判出 58 项技术（54 假阳性），修复后应只留真阳性。
//
// 这里直接断言各关键词的强弱分类——正是这些词的 OR 命中造成了海量误判。
func TestWeakKeywordRegressionDVWA(t *testing.T) {
	// 当年造成假阳性的通用词（应全部判弱 → 不再单独构成识别）
	falsePositiveKeywords := []string{
		"login", "username", "password", "User", "Application", "login.php",
		`type="password"`, "must-revalidate", "login_logo", "/login", "登录",
	}
	for _, k := range falsePositiveKeywords {
		if !weakKeyword(k) {
			t.Errorf("通用词 %q 应判弱（否则会继续造成假阳性）", k)
		}
	}
	// 真阳性的特征串（应判强 → 仍能识别）
	truePositiveKeywords := []string{
		"dvwa/css/login.css",
		"dvwa/images/login_logo.png",
	}
	for _, k := range truePositiveKeywords {
		if weakKeyword(k) {
			t.Errorf("DVWA 特征串 %q 应判强（否则真指纹被误杀）", k)
		}
	}
}

// TestWeakKeywordLowEntropyShortTokens 是**短词误判回归**（在线靶场实测）：
// EHole 导入的关键词混入 `oa` / `url` / `nas` / `360` / `vop` 这类低熵短串，
// 单独命中会把无关产品判成命中——实测 DVWA 被判出 VOP（17 条 CVE）、
// Jiusi-OA（关键词 oa）、Dahua-DSS（关键词 url），
// testasp（IIS）被判出 35Mail（关键词 35）、Jiusi-OA。
func TestWeakKeywordLowEntropyShortTokens(t *testing.T) {
	for _, k := range []string{
		"oa", "url", "uri", "host", "nas", "san", "dns", "vop", "voip",
		"360", "8000", "35", "wso", "dss", "wcm", "hfs", "aten",
		"mail", "sessid", "session", "firewall", "router", "gateway",
		"theme", "modules", "plugins", "configuration", "redirect",
		"rums", "url2", "dss2",
	} {
		if !weakKeyword(k) {
			t.Errorf("低熵短串 %q 应判弱（否则会把无关产品判成命中）", k)
		}
	}
}

// TestWeakKeywordStructuredNotOverFiltered 是**误杀回归**：带路径 / 标签 /
// 复合词结构的关键词，其短 token 仍具区分度，不得被短词闸门误杀。
func TestWeakKeywordStructuredNotOverFiltered(t *testing.T) {
	for _, k := range []string{
		"dvwa/css/login.css", "dvwa/images/login_logo.png",
		"wp-content", "image/aaa.png", "nginx/1.31.6",
		"<title>Damn Vulnerable Web App (DVWA) - Login</title>",
		"switchingserverpopup", "lgdynacodebtn", "dahuadefined",
	} {
		if weakKeyword(k) {
			t.Errorf("结构化关键词 %q 应判强（否则真指纹被误杀）", k)
		}
	}
}

// TestProductNameOnly 裸产品名形态需第二关键词佐证（防「README 提一次
// VMware 就把站点判成 VMware Horizon」类误判）。
func TestProductNameOnly(t *testing.T) {
	for _, k := range []string{"VMware", "Consul", "MacOS", "Apache", "Tomcat"} {
		if !productNameOnly(k) {
			t.Errorf("裸产品名 %q 应需佐证", k)
		}
	}
	for _, k := range []string{
		"dvwa/css/login.css", "nginx/1.31.6", "switchingserverpopup",
		"help.mail.35.com", "Dahua-DSS", "lgdynacodebtn",
	} {
		if productNameOnly(k) {
			t.Errorf("带结构关键词 %q 不应需佐证", k)
		}
	}
}
