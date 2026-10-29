// 前端形状预筛：模板转换有四个前端（path 形态 / raw 请求形态 / afrog
// 经典形态 / 协议模板），每个前端都要先对整份文件做一次 yaml.Unmarshal。
// 而真实模板库绝大多数文件只有一种形状——旧实现里 convertAny 依次尝试
// 三个 HTTP 前端，afrog 模板要白解析两次（约 2/3 的 YAML 解析是纯浪费）。
//
// 这里用一次廉价字节扫描（不做 YAML 解析）判断文件顶层映射里可能出现
// 哪些前端需要的键，把「必然返回空」的前端整段跳过。真实 afrog 语料
// 因此从 3 次解析降到 1 次。
//
// 安全性（宁多解析一次，不漏转换）：scanFrontShape 只做排除法，返回位图
// 是「实际可能命中前端」的超集。判据是各前端成功转换的必要条件：
//   - Convert/ConvertRaw：yaml 解析后 len(doc.HTTP)+len(doc.Requests) > 0，
//     即顶层映射必须出现字面键 http / requests；
//   - ConvertAfrog：len(doc.Rules) > 0，即顶层出现 rules 键；
//   - ConvertNetwork：len(doc.TCP)+len(doc.DNS)+len(doc.SSL) > 0，
//     即顶层出现 tcp / dns / ssl 键。
//
// yaml.v3 对结构体字段按 tag 精确匹配（大小写敏感），所以这些键必须
// 字面解码为上述名字。任何无法廉价确认的 YAML 形态（flow 根映射、
// 锚点/别名/merge 键、显式键、标签、引号转义、异常缩进等）一律返回
// frontAll，交给完整解析流程裁决。
package nuclei

import "bytes"

// frontShape 前端形状位图：置位 = 该前端「可能命中」，必须尝试；
// 清零 = 已确认该前端对这份数据必然返回空，可安全跳过。
type frontShape uint8

const (
	frontHTTP  frontShape = 1 << iota // Convert / ConvertRaw（顶层 http:/requests:）
	frontAfrog                        // ConvertAfrog（顶层 rules:）
	frontNet                          // ConvertNetwork（顶层 tcp:/dns:/ssl:）
	frontAll   = frontHTTP | frontAfrog | frontNet
)

// frontKeys 目标顶层键 → 前端位。必须与 tplDoc/afrogDoc/netDoc 的
// yaml tag 字面量保持一致（大小写敏感）。
var frontKeys = [...]struct {
	name string
	bit  frontShape
}{
	{"http", frontHTTP},
	{"requests", frontHTTP},
	{"rules", frontAfrog},
	{"tcp", frontNet},
	{"dns", frontNet},
	{"ssl", frontNet},
}

// scanFrontShape 廉价字节级前端形状预筛（见文件头注释的等价性论证）。
// 返回位图是「实际可能命中前端」的超集；frontAll 表示无法确认，保守全试。
func scanFrontShape(data []byte) frontShape {
	// 四个前端共用的两道门禁：512KB 上限与 interactsh 外部回调跳过。
	// 命中任一条时四个前端都必然返回空。
	if len(data) > 512*1024 {
		return 0
	}
	if bytes.Contains(data[:min(3000, len(data))], []byte("interactsh")) {
		return 0
	}

	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM

	var shape frontShape
	baseIndent := -1 // 顶层块映射键的缩进；-1 = 尚未见到结构行
	for off := 0; off < len(data); {
		line, next := nextYAMLLine(data, off)
		off = next

		// 行首缩进：只数空格；tab 违反 YAML 缩进规则（yaml 会报错），
		// 但为免漏判一律按不确定处理。
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent < len(line) && line[indent] == '\t' {
			return frontAll
		}
		rest := line[indent:]
		if len(rest) == 0 || rest[0] == '#' {
			continue // 空行 / 注释行
		}
		if baseIndent < 0 && rest[0] == '%' {
			continue // 指令行（%YAML / %TAG）
		}
		if isDocMarker(rest, "---") {
			// 文档起始标记：带内联内容说明根是 flow/复合形态，保守全试；
			// 其后是第二个文档（yaml.Unmarshal 只解首文档），继续扫描只会
			// 产生「多解析一次」的假阳性，不会漏判。
			if after := rest[3:]; len(bytes.TrimSpace(after)) > 0 && bytes.TrimSpace(after)[0] != '#' {
				return frontAll
			}
			continue
		}
		if isDocMarker(rest, "...") {
			continue // 文档结束标记
		}
		if baseIndent < 0 {
			if rest[0] == '{' || rest[0] == '[' {
				return frontAll // flow 根映射/序列：无法廉价枚举键
			}
			if rest[0] == '-' && (len(rest) == 1 || rest[1] == ' ' || rest[1] == '\t') {
				// 根序列：四个前端 unmarshal 到结构体都会报错 → 必然全空
				return 0
			}
			baseIndent = indent
		} else if indent < baseIndent {
			// 顶层块映射的键缩进必须一致；出现更浅的结构只可能是非法
			// YAML 或后续文档，保守全试。
			return frontAll
		}
		if indent != baseIndent {
			continue // 嵌套内容，与顶层键无关
		}

		// ---- 顶层键行 ----
		// 可能把键「藏起来」的形态：锚点/别名、merge 键、标签、显式键、
		// flow 行首、序列项、引号转义键——一律保守全试。
		switch rest[0] {
		case '?', '&', '*', '!', '<', '{', '[', '-':
			return frontAll
		case '"', '\'':
			if bit, ok := matchQuotedKey(rest); ok {
				shape |= bit
				continue
			}
			// 非简单引号键：可能是多行/转义形态（如 "ht\+换行+tp"），
			// 无法廉价确认，保守全试。
			return frontAll
		}
		// 块映射里每个顶层行都应是键；不是键的行（flow 续行、非法行）
		// 不会引入顶层键，忽略即可。
		if bit, ok := matchPlainKey(rest); ok {
			shape |= bit
		}
	}
	return shape
}

// isDocMarker 行是否为 YAML 文档标记（--- / ...）：标记后必须是空白、
// 注释或行尾（`---foo` 是普通标量，不是标记）。
func isDocMarker(line []byte, mark string) bool {
	if !bytes.HasPrefix(line, []byte(mark)) {
		return false
	}
	return len(line) == len(mark) || line[len(mark)] == ' ' ||
		line[len(mark)] == '\t' || line[len(mark)] == '#'
}

// nextYAMLLine 取下一物理行并返回下一行起点。YAML 的换行集合比 \n 宽：
// CR(#xD)、LF(#xA)、NEL(#x85)、LS(#x2028)、PS(#x2029) 都算行分隔符
// （yaml.v3 is_break 同口径）；CRLF 算一个。只看 \n 会把 `name: x\rhttp:`
// 这类行误判成嵌套内容而漏掉顶层 http 键（fuzz 实测案例）。
func nextYAMLLine(data []byte, off int) (line []byte, next int) {
	for i := off; i < len(data); i++ {
		switch {
		case data[i] == '\n':
			return data[off:i], i + 1
		case data[i] == '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				return data[off:i], i + 2
			}
			return data[off:i], i + 1
		case data[i] == 0xC2 && i+1 < len(data) && data[i+1] == 0x85:
			return data[off:i], i + 2 // NEL (#x85)
		case data[i] == 0xE2 && i+2 < len(data) && data[i+1] == 0x80 &&
			(data[i+2] == 0xA8 || data[i+2] == 0xA9):
			return data[off:i], i + 3 // LS (#x2028) / PS (#x2029)
		}
	}
	return data[off:], len(data)
}

// matchPlainKey 顶层键行是否为 plain 形态的目标键（name 后允许空格再接
// 冒号——yaml.v3 接受 `http :` 这种写法；冒号后必须是空白/注释/行尾，
// 这是块映射键的终结条件）。
func matchPlainKey(line []byte) (frontShape, bool) {
	for _, k := range frontKeys {
		if !bytes.HasPrefix(line, []byte(k.name)) {
			continue
		}
		if _, ok := keyTerminator(line[len(k.name):]); ok {
			return k.bit, true
		}
	}
	return 0, false
}

// matchQuotedKey 顶层键行是否为简单引号形态的目标键（键内容不含转义，
// 因此与 plain 键解码结果相同）。
func matchQuotedKey(line []byte) (frontShape, bool) {
	q := line[0]
	for _, k := range frontKeys {
		if !bytes.HasPrefix(line[1:], []byte(k.name)) {
			continue
		}
		i := 1 + len(k.name)
		if i >= len(line) || line[i] != q {
			continue
		}
		if _, ok := keyTerminator(line[i+1:]); ok {
			return k.bit, true
		}
	}
	return 0, false
}

// keyTerminator 判断键名之后是否到达块映射键的冒号终结符：
// [ \t]* ':' (空白 | '#' | 行尾)。
func keyTerminator(rest []byte) (int, bool) {
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != ':' {
		return 0, false
	}
	i++
	if i == len(rest) {
		return i, true
	}
	switch rest[i] {
	case ' ', '\t', '#':
		return i, true
	}
	return 0, false
}
