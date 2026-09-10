// favicon mmh3 指纹：FOFA 生态的 icon_hash 算法——内容 base64 编码
// （codecs.encode 语义，含结尾换行）后取 murmur3 x86_32（seed 0），
// 按有符号 int32 语义返回。算法已与官方 mmh3 C 实现逐位锚定
// （校准脚本 build/mm3_ref.py；测试内含锚定向量）。
package sitelens

import (
	"encoding/base64"
	"math/bits"
	"strings"

	"cnb.cool/feng-qiao/sitelens/internal/httpx"
)

// murmur3x8632 MurmurHash3 x86 32 位（seed 固定 0）。
func murmur3x8632(data []byte) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := uint32(0)
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	if len(tail) >= 3 {
		k ^= uint32(tail[2]) << 16
	}
	if len(tail) >= 2 {
		k ^= uint32(tail[1]) << 8
	}
	if len(tail) >= 1 {
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// fofaBase64 复刻 Python codecs.encode(content, "base64")（即
// base64.encodebytes）：76 字符换行、每行以 \n 结尾、空输入输出空。
func fofaBase64(content []byte) []byte {
	if len(content) == 0 {
		return nil
	}
	enc := base64.StdEncoding.EncodeToString(content)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		j := i + 76
		if j > len(enc) {
			j = len(enc)
		}
		b.WriteString(enc[i:j])
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// FaviconHash FOFA icon_hash：与 Python
// mmh3.hash(codecs.encode(content, "base64")) 逐位一致（含换行语义）。
func FaviconHash(content []byte) int64 {
	return int64(int32(murmur3x8632(fofaBase64(content))))
}

// faviconMaxBytes favicon 采集尺寸上限（超过按未采集处理）。
const faviconMaxBytes = 512 * 1024

// FaviconHashOf 抓取站点默认 favicon（/favicon.ico）并计算 icon_hash。
// 失败/非 200/超限一律返回 0（表示未采集；icon_hash 规则对 0 不匹配）。
func FaviconHashOf(client *httpx.Client, baseURL string) int64 {
	if client == nil || baseURL == "" {
		return 0
	}
	u := strings.TrimRight(baseURL, "/") + "/favicon.ico"
	resp, err := client.GetDirect(u)
	if err != nil || resp == nil || resp.Status != 200 {
		return 0
	}
	if len(resp.Body) == 0 || len(resp.Body) > faviconMaxBytes {
		return 0
	}
	return FaviconHash([]byte(resp.Body))
}
