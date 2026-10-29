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
		"www.gov.cn",              // 无协议补 https
		"https://flk.npc.gov.cn/", // 子域
		"https://www.mps.gov.cn",  // 部委子域
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

// TestValidateBlocksCloudMetadata 云厂商元数据端点必须**永久**被拒：
// 即使 allow_private 开启（授权内网扫描的正常姿态）也不放行——
// 元数据服务里放着临时 IAM 凭证，扫到即等于把凭证交出去（BUG-003）。
func TestValidateBlocksCloudMetadata(t *testing.T) {
	old := allowPrivate
	defer func() { allowPrivate = old }()

	ips := []string{
		"169.254.169.254", // AWS / GCP / Azure / 阿里云
		"100.100.100.200", // 阿里云 ECS
		"fd00:ec2::254",   // AWS IPv6
	}
	for _, priv := range []bool{false, true} {
		allowPrivate = priv
		for _, ip := range ips {
			raw := "http://" + ip + "/latest/meta-data/"
			// resolve 开与关都必须拒——元数据保护不得依赖任何开关。
			for _, resolve := range []bool{false, true} {
				if _, _, _, err := Validate(raw, resolve); err == nil {
					t.Errorf("allow_private=%v resolve=%v 时 %s 应被拒（云元数据端点不可配置关闭）",
						priv, resolve, ip)
				}
			}
			if err := ValidateHostPort("tcp", ip, 80, false); err == nil {
				t.Errorf("allow_private=%v 时 netx 目标 %s 应被拒", priv, ip)
			}
		}
	}

	// 主机名形态同样永久阻断。
	for _, host := range []string{"metadata.google.internal", "metadata.goog", "instance-data.ec2.internal"} {
		allowPrivate = true
		if _, _, _, err := Validate("http://"+host+"/", false); err == nil {
			t.Errorf("allow_private=true 时 %s 应被拒", host)
		}
	}
}

// TestValidateAllowPrivateStillRelaxesPrivate 回归：allow_private 仍应放宽
// 普通私网/本机（授权靶场场景），只是不再顺带放宽云元数据端点。
func TestValidateAllowPrivateStillRelaxesPrivate(t *testing.T) {
	old := allowPrivate
	defer func() { allowPrivate = old }()

	allowPrivate = true
	if _, _, _, err := Validate("http://127.0.0.1:8080/", true); err != nil {
		t.Errorf("allow_private=true 时本机应放行：%v", err)
	}
	if _, _, _, err := Validate("http://10.0.0.5/", true); err != nil {
		t.Errorf("allow_private=true 时私网地址应放行：%v", err)
	}

	// resolve=true（引擎默认）时，allow_private=false 应拦下私网/本机。
	allowPrivate = false
	if _, _, _, err := Validate("http://127.0.0.1:8080/", true); err == nil {
		t.Errorf("allow_private=false 时本机应被拒")
	}
	if _, _, _, err := Validate("http://10.0.0.5/", true); err == nil {
		t.Errorf("allow_private=false 时私网地址应被拒")
	}
}
