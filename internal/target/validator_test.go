// gov.cn 代码级硬保护回归测试：政府网站任何形态的目标都必须被拒，
// 且不受 resolve 开关影响；非 gov.cn 域名不受波及。
package target

import "testing"

func TestValidateBlocksGovCn(t *testing.T) {
	for _, raw := range []string{
		"https://www.gov.cn",
		"https://www.gov.cn/xinwen",
		"http://gov.cn",
		"https://www.gov.cn:8443/",
		"www.gov.cn",               // 无协议补 https
		"https://flk.npc.gov.cn/",  // 子域
		"https://www.mps.gov.cn",   // 部委子域
	} {
		if _, _, _, err := Validate(raw, false); err == nil {
			t.Errorf("%s 应被拒扫（gov.cn 硬保护）", raw)
		}
	}
}

func TestValidateGovCnUnaffected(t *testing.T) {
	// 相似但非 gov.cn 的域名不得误伤（gov.com / govcn.cn / example.gov.cn 不存在但 gov.cn 以外后缀放行）
	for _, raw := range []string{
		"https://www.gov.com",
		"https://govcn.cn",
		"https://example.com",
	} {
		if _, _, _, err := Validate(raw, false); err != nil {
			t.Errorf("%s 不应被 gov.cn 规则误伤：%v", raw, err)
		}
	}
}

func TestValidateHostPortBlocksGovCn(t *testing.T) {
	if err := ValidateHostPort("tcp", "www.gov.cn", 443, false); err == nil {
		t.Errorf("netx 目标 gov.cn 应被拒")
	}
	if err := ValidateHostPort("dns", "www.gov.cn", 0, false); err == nil {
		t.Errorf("netx dns 目标 gov.cn 应被拒")
	}
	if err := ValidateHostPort("tcp", "example.com", 443, false); err != nil {
		t.Errorf("非 gov.cn 目标不应被拒：%v", err)
	}
}
