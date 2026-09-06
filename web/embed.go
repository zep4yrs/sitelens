// Package web 内嵌前端静态资源（单二进制交付）。
package web

import "embed"

//go:embed *.html js/*.js
var FS embed.FS
