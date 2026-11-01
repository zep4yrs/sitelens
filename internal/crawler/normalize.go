package crawler

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

// 本文件：链接归一化（CP-01）。
//
// 目标：同一语义的 URL 只有一种规范形态——去 fragment、去默认端口、
// host/scheme 小写、query 参数按 (key,value) 排序、去末尾冗余斜杠（根路径除外）。
// 归一化结果用于去重键；resolve 出来的候选 URL 也走同一套规范化，保证
// 抓取与去重看到的是同一个地址。

// skipAssetExts 非 HTML 页面后缀：二进制/静态资源不值得当页面爬
// （爬回来也只能当垃圾页，还挤占 MaxPages 预算）。用后缀判断，query 不参与。
var skipAssetExts = map[string]bool{
	// 图片
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".bmp": true, ".ico": true, ".svg": true, ".avif": true, ".tif": true, ".tiff": true,
	// 字体
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	// 音视频
	".mp3": true, ".mp4": true, ".m4a": true, ".webm": true, ".ogg": true,
	".wav": true, ".avi": true, ".mov": true, ".flac": true, ".aac": true, ".mkv": true,
	// 压缩包/安装包/镜像/二进制
	".zip": true, ".gz": true, ".tgz": true, ".tar": true, ".rar": true, ".7z": true,
	".bz2": true, ".xz": true, ".exe": true, ".dll": true, ".bin": true, ".so": true,
	".dylib": true, ".apk": true, ".ipa": true, ".dmg": true, ".iso": true, ".msi": true,
	".deb": true, ".rpm": true, ".wasm": true,
	// 文档（正文大、非 HTML）
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".rtf": true,
	// 静态前端资源（文本但不是页面，爬了只会污染页面清单）
	".css": true, ".js": true, ".mjs": true, ".map": true,
}

// isStaticAssetPath 路径后缀是否非页面资源。
func isStaticAssetPath(p string) bool {
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return false
	}
	ext := strings.ToLower(p[i:])
	return skipAssetExts[ext]
}

// canonicalHost 规范化 host：小写、去默认端口（http:80 / https:443），
// 保留 IPv6 字面量方括号。
func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || port == defaultPort(u.Scheme) {
		if strings.Contains(host, ":") {
			return "[" + host + "]" // IPv6 字面量
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

// defaultPort scheme 的默认端口（未知 scheme 返回空）。
func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// hostKey 同域判定键：hostname + 有效端口（显式端口或协议默认端口）。
// 这样 http://a.com 与 http://a.com:80 同域，而 a.com:8080 与 a.com:9090 不同域。
func hostKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// canonicalQuery 对 query 参数做稳定排序（先 key 再 value），返回编码后的
// RawQuery（无参数返回空串）。这样 ?b=2&a=1 与 ?a=1&b=2 归一为同一地址。
func canonicalQuery(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(url.Values, len(q))
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			out.Add(k, v)
		}
	}
	return out.Encode()
}

// canonicalizeURL 原地规范化：scheme/host 小写、去默认端口、去 fragment、
// 稳定排序 query。
func canonicalizeURL(u *url.URL) {
	if u == nil {
		return
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = canonicalHost(u)
	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = canonicalQuery(u)
}

// normalize 生成去重键：canonicalizeURL + 去末尾斜杠（根路径 "/" 保留）。
//
// 注意：只用于判重，不作为展示/请求地址（请求地址由 resolve 产出，同样已规范化，
// 但保留末尾斜杠语义）。
func normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	canonicalizeURL(u)
	if u.Path == "" {
		u.Path = "/"
	}
	if u.Path != "/" {
		u.Path = strings.TrimRight(u.Path, "/")
		if u.Path == "" {
			u.Path = "/"
		}
	}
	return u.String()
}
