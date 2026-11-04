// 模板情报行加载与合并（update-tplintel 产物）。
package intel

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"os"
)

// LoadTplIntel 从 tpl_intel.json.gz 加载模板情报行（文件缺失返回 (nil, nil)）。
//
// C2-06：文件存在但读取/解压/解析失败时 log 留痕。调用方（server 启动、
// reloadData、CLI）目前只在 err==nil 时合并，错误本身不落日志——若不在
// 这里打日志，"模板情报整批缺失"在运行期完全不可见。
func LoadTplIntel(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		log.Printf("intel: 模板情报文件打开失败（%s）：%v", path, err)
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		log.Printf("intel: 模板情报文件解压失败（%s）：%v", path, err)
		return nil, err
	}
	var box struct {
		Rows []Entry `json:"rows"`
	}
	if err := json.NewDecoder(gz).Decode(&box); err != nil {
		log.Printf("intel: 模板情报文件解析失败（%s）：%v", path, err)
		return nil, err
	}
	return box.Rows, nil
}

// AttachTplIntel 合并模板情报行进 vuln_kb 主索引（负 ID 段避开精选行的
// 正 ID 空间），并重建关键词索引。调用须在首次 Match 之前。
//
// 与扫描/覆盖合并并发时按 BUG-014 的同一把写锁换代：append+重建索引
// 整体完成，读侧不会看到「元素已加、索引未建」的中间态。
//
// C-10：loadMu 与 ensureDecoded 的挂起队列重放互斥（decoded 判断不能再
// 裸读；若与解码并发，可能出现"判断未解码 → 写 pendingTpl" 与
// "重放后清空 pendingTpl" 交错，模板行静默丢失）。
func (k *KB) AttachTplIntel(rows []Entry) {
	if len(rows) == 0 {
		return
	}
	k.loadMu.Lock()
	defer k.loadMu.Unlock()
	k.attachTplIntelLocked(rows)
}

// attachTplIntelLocked 合并实现：调用方须已持 loadMu 写锁（ensureDecoded
// 重放挂起模板行时直接调本函数，避免重入 loadMu）。
func (k *KB) attachTplIntelLocked(rows []Entry) {
	if len(rows) == 0 {
		return
	}
	if !k.decoded {
		// A5 惰性：尚未解码时先挂起，ensureDecoded 末尾按序并入
		k.pendingTpl = append(k.pendingTpl, rows...)
		return
	}
	k.vulnsMu.Lock()
	defer k.vulnsMu.Unlock()
	// 负 ID 段从既有最小值继续（重复调用/Release 重放不会产生重复 ID）。
	next := int64(0)
	for i := range k.vulns {
		if k.vulns[i].ID < next {
			next = k.vulns[i].ID
		}
	}
	for _, r := range rows {
		next--
		r.ID = next
		k.vulns = append(k.vulns, r)
	}
	k.buildIndex()
}
