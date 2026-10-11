package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"

	"sitelens-wails/internal/portpolicy"
)

// 端口决策：壳偏好 > 配置原文 web.listen > 默认 5087，被占用才随机空闲端口。
// 纯决策规则在 internal/portpolicy（可跨平台单测）；本文件只做 IO：
// 读偏好文件、读用户配置、回写协商结果。

// prefsPath 壳偏好文件落用户配置目录（%APPDATA%/SiteLens-Wails/desktop-prefs.json）。
func prefsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "SiteLens-Wails", "desktop-prefs.json"), nil
}

// userConfigPath 用户配置文件路径（与 writeUserConfig 同源）。
func userConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "SiteLens-Wails", "config.yml"), nil
}

// readPrefPort 读偏好端口；文件缺失/损坏返回 0（回退配置/默认）。
func readPrefPort() int {
	p, err := prefsPath()
	if err != nil {
		return 0
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	var v struct {
		Port int `json:"port"`
	}
	if json.Unmarshal(b, &v) != nil || !portpolicy.Valid(v.Port) {
		return 0
	}
	return v.Port
}

// writePrefPort 回写偏好端口（协商结果）。失败只记日志——端口仍是本次可用的，
// 不该因偏好写不进去就阻断启动（降级路径记入 shell.log，不静默漂移）。
func writePrefPort(port int) {
	p, err := prefsPath()
	if err != nil {
		log.Printf("偏好端口回写跳过：%v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		log.Printf("偏好端口回写跳过：%v", err)
		return
	}
	b, _ := json.MarshalIndent(map[string]any{"port": port}, "", "  ")
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		log.Printf("偏好端口回写跳过：%v", err)
	}
}

// chooseListen 决策最终监听地址：优先尝试偏好/配置/默认端口，能占用就用
// （回写偏好保持粘性）；被占用才向系统要随机空闲端口（同样回写，下次认领）。
func chooseListen() (string, int) {
	confPort := 0
	if p, err := userConfigPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			confPort = portpolicy.ParseConfListenPort(string(b))
		}
	}
	port, source := portpolicy.Resolve(readPrefPort(), confPort)
	if l, err := net.Listen("tcp", portpolicy.Listen(port)); err == nil {
		_ = l.Close() // 释放后由引擎重新绑定，窗口期极短；失败会退到随机
		log.Printf("端口 %d 可用（来源：%s）", port, portpolicy.Describe(source))
		writePrefPort(port)
		return portpolicy.Listen(port), port
	}
	log.Printf("端口 %d 被占用（来源：%s），改用随机空闲端口", port, portpolicy.Describe(source))
	rp, err := freePort()
	if err != nil {
		log.Fatalf("取空闲端口失败: %v", err)
	}
	writePrefPort(rp)
	return portpolicy.Listen(rp), rp
}
