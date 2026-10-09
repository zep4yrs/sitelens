//go:build race

package server

// raceEnabled 在 -race 构建下为真（build tag race 由 go test -race 注入）。
const raceEnabled = true
