package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ID 前缀（人类可读、便于在 JSONL 里按类型 grep）。
const (
	prefixEntryPoint   = "ep"
	prefixVulnNode     = "vn"
	prefixEvidence     = "ev"
	prefixEvidenceLink = "lnk"
	prefixDataflow     = "df"
	prefixCWERel       = "cwe"
	prefixChainNode    = "cn"
	prefixChainEdge    = "ce"
	prefixPrivChange   = "pc"
	prefixImpact       = "im"
)

// idHexLen 是哈希截断后的十六进制字符数（12 = 48 bit）。碰撞概率对单次
// 扫描的实体量级可忽略；截断换取可读的日志/CLI 输出。
const idHexLen = 12

// makeID 由内容确定性生成稳定 ID：前缀 + '_' + 内容哈希。
//
// 关键性质（ID 稳定性测试锁死）：
//
//   - 相同事实 → 相同 ID（跨进程、跨扫描、跨重启一致）；
//   - 不同事实 → 极大概率不同 ID；
//   - 各段用「长度前缀 + 值」编码，故 parts=["ab","c"] 与 ["a","bc"] 不会碰撞。
//
// 不含时间戳/随机数/自增计数——这是与 3.0 自增 ID 的本质区别，
// 也是 5.0 ML 能跨扫描聚合同一事实的前提。
func makeID(prefix string, parts ...string) string {
	h := sha256.New()
	var lenBuf [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(p)))
		h.Write(lenBuf[:])
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return prefix + "_" + hex.EncodeToString(sum[:])[:idHexLen]
}

// EntryPointID 入口点稳定 ID：由「来源 + 形态 + 定位」决定。
// 黑盒入口定位用 URL/Method/Param；白盒入口定位用 File/Func。
func EntryPointID(origin, kind, url, method, param, file, fn string) string {
	return makeID(prefixEntryPoint,
		norm(origin), norm(kind), norm(url), norm(method), norm(param), norm(file), norm(fn))
}

// EvidenceID 证据稳定 ID：由证据本身的定位 + 内容摘要决定。
// 同一响应的同一摘录无论被多少实体引用，ID 恒定（引用去重的前提）。
func EvidenceID(origin, kind, source, url, file string, line int, body string) string {
	return makeID(prefixEvidence,
		norm(origin), norm(kind), norm(source), norm(url), norm(file),
		strconv.Itoa(line), bodyDigest(body))
}

// VulnNodeID 漏洞节点稳定 ID。黑盒用 check_id + url + param 定位；
// 白盒用 rule_id + file + line 定位。origin 参与哈希，故同名 check 的
// 黑白盒节点天然区分。
func VulnNodeID(origin, checkID, ruleID, url, param, file string, line int) string {
	return makeID(prefixVulnNode,
		norm(origin), norm(checkID), norm(ruleID), norm(url), norm(param),
		norm(file), strconv.Itoa(line))
}

// EvidenceLinkID 黑白盒关联边稳定 ID：由两端稳定 ID + 关联依据决定。
func EvidenceLinkID(blackboxVulnID, whiteboxID, basis string) string {
	return makeID(prefixEvidenceLink, norm(blackboxVulnID), norm(whiteboxID), norm(basis))
}

// DataflowID 数据流稳定 ID：由文件 + 函数 + source/sink 定位决定。
func DataflowID(file, fn, param string, sinkLine int) string {
	return makeID(prefixDataflow, norm(file), norm(fn), norm(param), strconv.Itoa(sinkLine))
}

// CWERelID CWE 关联稳定 ID：由「关联主体 + CWE + 来源」决定。
func CWERelID(subjectKind, subjectID, cweID, source string) string {
	return makeID(prefixCWERel, norm(subjectKind), norm(subjectID), norm(cweID), norm(source))
}

// ChainNodeID 攻击链节点稳定 ID：由节点类型 + 引用实体决定。
func ChainNodeID(kind, refID string) string {
	return makeID(prefixChainNode, norm(kind), norm(refID))
}

// ChainEdgeID 攻击链边稳定 ID：由两端节点 + 边类型决定。
// 注意不含 derived_from——同一条边补强证据后 ID 保持稳定，便于追踪。
func ChainEdgeID(from, to, kind string) string {
	return makeID(prefixChainEdge, norm(from), norm(to), norm(kind))
}

// PrivChangeID 权限变化稳定 ID：由「从/到 + 机制 + 关联发现」决定。
func PrivChangeID(from, to, mechanism, findingID string) string {
	return makeID(prefixPrivChange, norm(from), norm(to), norm(mechanism), norm(findingID))
}

// ImpactID 影响稳定 ID：由影响类型 + 关联漏洞节点决定。
func ImpactID(kind, vulnID string) string {
	return makeID(prefixImpact, norm(kind), norm(vulnID))
}

// bodyDigest 证据正文的内容摘要（截断哈希），既参与 ID 又便于比对。
// 正文可能很大（响应快照），只取哈希不存全文副本。
func bodyDigest(body string) string {
	if body == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])[:idHexLen]
}

// norm 归一化参与哈希的字段：去首尾空白 + 统一小写。
// URL/方法/参数名/技术名等大小写不敏感，归一化避免 "GET"/"get" 产生双份实体。
func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// IDFields 供测试与调试：把 ID 拆回（前缀, 哈希）二元组。
// 非法 ID 返回 ok=false。
func IDFields(id string) (prefix, digest string, ok bool) {
	i := strings.IndexByte(id, '_')
	if i <= 0 || i == len(id)-1 {
		return "", "", false
	}
	p, h := id[:i], id[i+1:]
	if len(h) != idHexLen {
		return "", "", false
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", "", false
	}
	return p, h, true
}

// PrefixOf 返回 ID 的前缀（类型），非法 ID 返回空串。
func PrefixOf(id string) string {
	p, _, _ := IDFields(id)
	return p
}

// ValidateID 校验稳定 ID 形态：前缀 + '_' + 12 位十六进制。
// wantPrefix 非空时一并校验前缀；用于跨实体引用前的快速合法性检查。
func ValidateID(id, wantPrefix string) error {
	p, _, ok := IDFields(id)
	if !ok {
		return fmt.Errorf("非法稳定 ID %q（应为 <prefix>_<12hex>）", id)
	}
	if wantPrefix != "" && p != wantPrefix {
		return fmt.Errorf("ID %q 前缀为 %q，期望 %q", id, p, wantPrefix)
	}
	return nil
}
