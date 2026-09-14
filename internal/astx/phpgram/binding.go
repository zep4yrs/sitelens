package phpgram

// PHP grammar 的 cgo 绑定（自持，第一方代码）。
//
// 为什么把 grammar 源码放进仓库（而不是走 go mod 依赖）：
//
//	tree-sitter 的 PHP grammar 在 C 源里写 `#include "tree_sitter/parser.h"`，
//	而 go mod vendor 只拷贝「含 Go 文件的包目录」内的文件，会丢弃
//	php/tree_sitter/ 这个无可执行 Go 文件的子目录 → CGO 编译报
//	tree_sitter/parser.h: No such file。CI 有 vendor 一致性门禁
//	（go mod vendor 后 git diff 必须为空），无法用「手动补文件」绕过。
//
//	故本包把所需 C/H 自持为第一方源码：第一方代码不参与 go mod vendor，
//	门禁不受影响，也不受 vendor 重建影响。
//
// 来源（上游，未改动）：
//
//	github.com/smacker/go-tree-sitter/php @ v0.0.0-20240827094217-dd81d9e9be82
//	（tree-sitter-php grammar 的 Go 绑定附带源码；MIT 许可）
//	文件：parser.c(生成) / scanner.c / scanner.h / parser.h / tree_sitter/*.h
//
// parser.c 为 tree-sitter 生成的源码（5.3MB，zlib 压缩后约 0.2MB）。
// scanner.c 通过 `#include "tree_sitter/parser.h"` 与 `"scanner.h"` 引用
// 本目录（及 tree_sitter/ 子目录）的头文件，故 CFLAGS 含 ${SRCDIR}。

/*
#cgo CFLAGS: -I${SRCDIR} -std=c11 -fPIC
#include "parser.h"
const TSLanguage *tree_sitter_php(void);
*/
import "C"

import (
	"unsafe"

	sitter "github.com/smacker/go-tree-sitter"
)

// GetLanguage 返回 PHP grammar 的 tree-sitter Language。
func GetLanguage() *sitter.Language {
	ptr := unsafe.Pointer(C.tree_sitter_php())
	return sitter.NewLanguage(ptr)
}
