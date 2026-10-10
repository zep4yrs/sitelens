//go:build !race

package server

// raceEnabled 在普通构建下为假。
const raceEnabled = false

// raceBuild 与 raceEnabled 同义，供时限口径函数读取（历史命名保留）。
const raceBuild = raceEnabled
