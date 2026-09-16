// Package web 内嵌前端静态资源（单二进制交付）。
package web

import "embed"

//go:embed *.html js/*.js css/*.css
var FS embed.FS

// MonacoFS 内嵌 Monaco Editor（25A 源码审计：web/monaco/vs，官方 min 发行版）。
// 单独 FS：体积大（约 12MB），经 /monaco/ 前缀由引擎静态服务。
//
//go:embed monaco
var MonacoFS embed.FS
