//go:build !race

package server

// raceEnabled 在普通构建下为假。
const raceEnabled = false
