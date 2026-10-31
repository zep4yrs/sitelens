package netsec

// NS-02 批量入口测试：端口探测 / 组合检测 / 多主机批量 / 展示辅助。

import (
	"crypto/x509"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDefaultPorts 默认常见端口集与规格一致。
func TestDefaultPorts(t *testing.T) {
	want := []int{21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200}
	if !reflect.DeepEqual(DefaultPorts, want) {
		t.Fatalf("DefaultPorts=%v, want %v", DefaultPorts, want)
	}
}

// TestCheckPorts 本地监听/关闭端口：只报开放端口、按入参顺序、读 banner 且
// 不向服务端发送任何数据。
func TestCheckPorts(t *testing.T) {
	// 开放端口 A：只 listen 不 accept（仅验证 connect 成功）
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = lnA.Close() })
	portA := lnA.Addr().(*net.TCPAddr).Port

	// 开放端口 B：接受连接 → 先确认客户端没发数据 → 再回 banner
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = lnB.Close() })
	portB := lnB.Addr().(*net.TCPAddr).Port
	clientSent := make(chan int, 1)
	go func() {
		c, aerr := lnB.Accept()
		if aerr != nil {
			clientSent <- -1
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := c.Read(buf) // 期望超时：n=0 说明客户端未发 payload
		clientSent <- n
		_, _ = c.Write([]byte("SSH-2.0-SiteLensTest\r\n"))
		time.Sleep(100 * time.Millisecond)
	}()

	closed := closedPort(t)
	hits := CheckPorts("127.0.0.1", []int{portB, portA, closed}, 400*time.Millisecond)
	if len(hits) != 2 {
		t.Fatalf("应只报 2 个开放端口, got %d: %+v", len(hits), hits)
	}
	// 输出顺序 = 入参顺序（closed 不产出）
	if !strings.Contains(hits[0].Title, strconv.Itoa(portB)) {
		t.Fatalf("第一条应是端口 B: %+v", hits[0])
	}
	if !strings.Contains(hits[0].Evidence, "SSH-2.0-SiteLensTest") {
		t.Fatalf("banner 未写入 evidence: %q", hits[0].Evidence)
	}
	if !strings.Contains(hits[1].Title, strconv.Itoa(portA)) {
		t.Fatalf("第二条应是端口 A: %+v", hits[1])
	}
	for _, f := range hits {
		if f.Check != "net-port" || f.Severity != "info" {
			t.Fatalf("未知端口应为 net-port/info: %+v", f)
		}
	}
	if n := <-clientSent; n != 0 {
		t.Fatalf("端口探测不应发送 payload, 服务端读到 %d 字节", n)
	}
}

// TestCheckPortsValidation 空 host / 非法端口 / 重复端口处理。
func TestCheckPortsValidation(t *testing.T) {
	if hits := CheckPorts("", nil, 0); hits != nil {
		t.Fatalf("空 host 应返回 nil: %+v", hits)
	}
	if hits := CheckPorts("127.0.0.1", []int{0, -1, 65536}, 100*time.Millisecond); hits != nil {
		t.Fatalf("非法端口应返回 nil: %+v", hits)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	if hits := CheckPorts("127.0.0.1", []int{port, port, port}, 300*time.Millisecond); len(hits) != 1 {
		t.Fatalf("重复端口应去重为 1 条, got %+v", hits)
	}
}

// TestCheckPortsDefaultSet ports 为空时使用 DefaultPorts（对 localhost 快速
// 探测；不关心是否有开放端口，只验证不 panic 且发现合法）。
func TestCheckPortsDefaultSet(t *testing.T) {
	hits := CheckPorts("127.0.0.1", nil, 100*time.Millisecond)
	for _, f := range hits {
		if f.Check != "net-port" {
			t.Fatalf("默认端口发现应为 net-port: %+v", f)
		}
		if f.Severity != "info" && f.Severity != "low" {
			t.Fatalf("默认端口严重度应为 info/low: %+v", f)
		}
	}
}

// TestSanitizeBanner 控制字符替换 + 截断。
func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("SSH-2.0-x\r\n\x00\x01 ok"))
	if strings.ContainsAny(got, "\r\n\x00\x01") {
		t.Fatalf("控制字符未清理: %q", got)
	}
	if !strings.Contains(got, "SSH-2.0-x") || !strings.Contains(got, "ok") {
		t.Fatalf("可打印内容丢失: %q", got)
	}
	long := sanitizeBanner([]byte(strings.Repeat("A", 400)))
	if len([]rune(long)) > 161 {
		t.Fatalf("banner 未截断: len=%d", len([]rune(long)))
	}
}

// TestCheckHosts 批量：去重/空值/分组，单个 host 有发现、不可达 host 也保留键。
func TestCheckHosts(t *testing.T) {
	key := rsaKeyBits(t, 2048)
	tpl := selfSignedTpl("acme-batch", nil, []net.IP{net.ParseIP("127.0.0.1")}, x509.SHA256WithRSA)
	host, port := newTLSCertFixture(t, tpl, key)

	got := CheckHosts([]string{host, " " + host + " ", "127.0.0.2", ""}, port, false, 100)
	if len(got) != 2 {
		t.Fatalf("应去重/去空白后剩 2 个 host, got %d: %v", len(got), got)
	}
	if len(got[host]) == 0 {
		t.Fatal("可达 host 应有发现")
	}
	mustFind(t, got[host], "tls-self-signed", "medium")
	if _, ok := got["127.0.0.2"]; !ok {
		t.Fatalf("不可达 host 也应保留 map 键: %v", got)
	}
	if len(got["127.0.0.2"]) != 0 {
		t.Fatalf("不可达 host 不应有发现: %+v", got["127.0.0.2"])
	}

	empty := CheckHosts(nil, 443, false, 0)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("空输入应返回空 map, got %v", empty)
	}
}

// TestHostURL 组合 URL 拼装（默认端口省略 / 非默认端口 / IPv6）。
func TestHostURL(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 443, "https://example.com/"},
		{"example.com", 8443, "https://example.com:8443/"},
		{"::1", 443, "https://[::1]/"},
		{"::1", 8443, "https://[::1]:8443/"},
	}
	for _, tc := range cases {
		if got := hostURL(tc.host, tc.port, "https"); got != tc.want {
			t.Fatalf("hostURL(%q,%d)=%q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

// TestSortFindings 稳定排序且不修改入参。
func TestSortFindings(t *testing.T) {
	in := []Finding{
		{Check: "tls-protocol", Title: "b"},
		{Check: "net-port", Title: "z"},
		{Check: "tls-protocol", Title: "a"},
	}
	out := SortFindings(in)
	// 先按 check 字典序（net-port < tls-protocol），再按 title
	if out[0].Check != "net-port" || out[1].Title != "a" || out[2].Title != "b" {
		t.Fatalf("排序结果错误: %+v", out)
	}
	if in[0].Title != "b" {
		t.Fatalf("不应修改入参: %+v", in)
	}
}
