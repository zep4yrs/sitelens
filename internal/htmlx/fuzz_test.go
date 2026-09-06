package htmlx

import (
	"testing"
)

// FuzzParse 随机/畸形 HTML 输入下解析不得 panic 或死循环。
func FuzzParse(f *testing.F) {
	f.Add("<html><title>a</title><form action=/x><input type=password name=p></form></html>")
	f.Add("<a href='unterminated>link</a>")
	f.Add("<meta name=generator content=>")
	f.Add("<script>var a = '</scr' + 'ipt>';</script>")
	f.Add("<<<<>>>>(((( ")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		doc := Parse(in)
		// 解析不应 panic；产物均派生自输入本身
		_ = doc.Title
		_ = doc.HasPassword
		for _, l := range doc.Links {
			_ = l
		}
		for _, s := range doc.ScriptSrcs {
			_ = s
		}
		for _, form := range doc.Forms {
			_ = form.Action
			for _, in := range form.Inputs {
				_ = in.Name + in.Type + in.ID + in.Placeholder + in.Value
			}
		}
	})
}
