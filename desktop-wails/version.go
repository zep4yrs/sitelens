package main

// Version 是 Wails 壳的版本号，与引擎版本（internal/server.Version）同源。
//
// 单一来源：发版脚本 tools/release_local.sh 从这里读取版本号，构建时不再
// 依赖 desktop/package.json（那是 Electron 壳的产物，切 wails 交付后不再
// 是版本权威）。改版本号时改这一处，脚本会同步校验引擎版本一致。
//
// 校验：tools/release_local.sh 会比对 Version 与 `sitelens.exe -version`
// 输出（引擎版本），不一致直接失败——历史上 5.0.0 发布时 README 下载入口
// 漏改，就是没有这层「文档/包/引擎三处一致」的硬闸。
const Version = "5.2.0"
