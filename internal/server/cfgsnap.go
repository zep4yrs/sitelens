package server

import (
	"cnb.cool/feng-qiao/sitelens/internal/config"
)

// cfgSnap 返回当前配置快照（A-09）。
//
// nil 表示未注入配置的裸 Server（仅测试会构造）；生产路径经 New 注入。
//
// 契约：返回的 *config.Config 视为**只读**。任何修改必须走设置页写侧
// （applySettings：深拷贝 → 改拷贝 → 原子换枪），禁止原地改旧结构——旧
// 结构可能正被并发的请求处理或进行中的扫描读取，原地写就是数据竞争。
func (s *Server) cfgSnap() *config.Config {
	if s == nil {
		return nil
	}
	return s.cfgPtr.Load()
}

// cloneConfig 深拷贝配置（设置页热更新的 copy-on-write 基础）。
//
// config.Config 目前只有 4 处引用类型字段（切片）：Scan.AllowHosts /
// Checks.DisabledIDs / Active.ProbePorts / Exploit.Authorized，其余全是
// 值类型嵌套结构。**新增引用类型字段时必须同步补进来**，否则写侧修改
// 会穿透到旧快照，破坏「进行中扫描/请求持旧快照」的语义。
func cloneConfig(c *config.Config) *config.Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Scan.AllowHosts = append([]string(nil), c.Scan.AllowHosts...)
	out.Checks.DisabledIDs = append([]string(nil), c.Checks.DisabledIDs...)
	out.Active.ProbePorts = append([]int(nil), c.Active.ProbePorts...)
	out.Exploit.Authorized = append([]string(nil), c.Exploit.Authorized...)
	return &out
}
