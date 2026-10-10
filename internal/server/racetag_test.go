//go:build race

package server

// raceEnabled 在 -race 构建下为真（build tag race 由 go test -race 注入）。
const raceEnabled = true

// raceBuild 与 raceEnabled 同义，供时限口径函数读取（历史命名保留）。
const raceBuild = raceEnabled
