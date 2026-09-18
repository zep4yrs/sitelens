package main

import (
	"strings"
	"testing"
)

// 启动页组装：占位符必须被替换；有 logo 资产时注入 data URI。
func TestBuildSplashHTML(t *testing.T) {
	h := buildSplashHTML()
	if strings.Contains(h, "{{LOGO}}") || strings.Contains(h, "{{VER}}") {
		t.Fatalf("占位符未替换: LOGO=%v VER=%v", strings.Contains(h, "{{LOGO}}"), strings.Contains(h, "{{VER}}"))
	}
	if len(splashPNG) > 0 && !strings.Contains(h, "data:image/png;base64,") {
		t.Fatal("splashPNG 非空但未注入 data URI")
	}
	if !strings.Contains(h, "fadeOut") || !strings.Contains(h, "setError") || !strings.Contains(h, "setStatus") {
		t.Fatal("启动页缺少外部接口（setStatus/setError/fadeOut）")
	}
}
