package versioncmp

import "testing"

// FuzzParse 随机版本串不得 panic；Parse 产出必须可被 Cmp 消费。
func FuzzParse(f *testing.F) {
	f.Add("1.2.3")
	f.Add("v10.0.18362")
	f.Add("")
	f.Add("...")
	f.Add("99999999999999999999")
	f.Add("1.2.3.4.5")
	f.Add("-1.-2")
	f.Add("ubuntu 20.04.3 LTS")
	f.Fuzz(func(t *testing.T, in string) {
		p := Parse(in)
		_ = Cmp(in, "1.0.0")
		_ = VersionIn(in, "<=2.0")
		_ = p
	})
}
