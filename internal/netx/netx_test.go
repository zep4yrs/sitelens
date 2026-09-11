package netx

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// loopback TCP echo 服务（收什么回什么，带前缀标记）。
func echoServer(t *testing.T, prefix string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil && n == 0 {
					return
				}
				_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write(append([]byte(prefix), buf[:n]...))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestParseTarget(t *testing.T) {
	for raw, want := range map[string]Target{
		"tcp://example.com:6379":  {Scheme: "tcp", Host: "example.com", Port: 6379},
		"tls://example.com:443":   {Scheme: "tls", Host: "example.com", Port: 443},
		"udp://10.0.0.1:161":      {Scheme: "udp", Host: "10.0.0.1", Port: 161},
		"dns://example.com/":      {Scheme: "dns", Host: "example.com"},
		"dns://example.com":       {Scheme: "dns", Host: "example.com"},
		"TCP://example.com:6379":  {Scheme: "tcp", Host: "example.com", Port: 6379},
		"tcp://example.com.:6379": {Scheme: "tcp", Host: "example.com", Port: 6379},
	} {
		got, err := ParseTarget(raw)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTarget(%q) = %+v, want %+v", raw, got, want)
		}
	}
	for _, bad := range []string{"example.com:6379", "tcp://example.com", "tcp://example.com:0",
		"tcp://example.com:99999", ""} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) 应报错", bad)
		}
	}
	// 协议白名单是 Validate 的职责：ftp 解析能过、闸会拦
	ftp, err := ParseTarget("ftp://example.com:21")
	if err != nil {
		t.Errorf("ParseTarget(ftp) 应解析成功（闸在 Validate）: %v", err)
	}
	if err := ftp.Validate(false); err == nil {
		t.Errorf("Validate(ftp) 应拦截")
	}
}

func TestValidateBlocksPrivateAndUnknownScheme(t *testing.T) {
	// 安全闸：私网/loopback/保留主机拒绝（resolve=false 也拦主机名规则）
	for _, raw := range []string{
		"tcp://localhost:6379", "tcp://127.0.0.1:6379", "tcp://10.0.0.1:6379",
		"tls://192.168.1.1:443", "tcp://metadata.google.internal:443",
		"udp://something.local:161", "ftp://example.com:21",
	} {
		tgt, err := ParseTarget(raw)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", raw, err)
			continue
		}
		if err := tgt.Validate(false); err == nil {
			// 127.0.0.1/10.0.0.1 等字面 IP 由 isBlockedIP 拦；域名类由黑名单拦
			t.Errorf("Validate(%q) 应拦截", raw)
		}
	}
}

func TestSendRecvEchoLoopback(t *testing.T) {
	const banner = "REDIS"
	addr, stop := echoServer(t, banner+" ")
	defer stop()
	host, portS, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portS)

	cfg := Config{TimeoutMS: 2000, MaxRounds: 2}
	conn, err := insecureDial(Target{Scheme: "tcp", Host: host, Port: port}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Send([]byte("PING\r\n")); err != nil {
		t.Fatal(err)
	}
	got, err := conn.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), banner+" PING") {
		t.Errorf("echo 回包不对: %q", got)
	}
	// 轮次上限：MaxRounds=2，第三轮 Send 报错
	_ = conn.Send([]byte("PING\r\n"))
	_, _ = conn.Recv()
	if err := conn.Send([]byte("OVER\r\n")); err == nil {
		t.Errorf("超过轮次上限应报错")
	}
}

func TestRecvRespectsMaxReadBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		big := make([]byte, 1<<20) // 1MB
		_, _ = conn.Write(big)
	}()
	host, portS, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portS)
	conn, err := insecureDial(Target{Scheme: "tcp", Host: host, Port: port},
		Config{TimeoutMS: 2000, MaxReadBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := conn.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4096 {
		t.Errorf("读取应被截断到 4096，实际 %d", len(got))
	}
}

func TestDialRejectsWithoutValidate(t *testing.T) {
	// Dial（带闸）对私网目标必须拒绝；insecureDial 不受影响（测试专用）
	tgt := Target{Scheme: "tcp", Host: "127.0.0.1", Port: 1}
	if _, err := Dial(tgt, Config{}, false); err == nil {
		t.Errorf("Dial 对 loopback 应拒绝")
	}
}

func TestDNSQueryRejectsBadType(t *testing.T) {
	if _, err := DNSQuery(Config{}, "example.com", "SRV1"); err == nil {
		t.Errorf("不支持的记录类型应报错")
	}
}

func TestDefaultsFallback(t *testing.T) {
	cfg := Config{}
	if cfg.timeout() != 5*time.Second || cfg.maxRead() != 64*1024 || cfg.maxRounds() != 4 {
		t.Errorf("零值默认回退不对: %+v", cfg)
	}
}
