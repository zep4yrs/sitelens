package modules

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"cnb.cool/feng-qiao/sitelens/internal/intel"
)

func TestServiceProbeMatchesBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprintf(conn, "SSH-2.0-OpenSSH_8.9p1\r\n")
			conn.Close()
		}
	}()

	rows := []intel.ServiceFPRow{
		{Service: "ssh", Pattern: `^SSH-\d\.\d`, Product: "OpenSSH", Version: "8.9"},
		{Service: "broken", Pattern: `(unclosed`, Product: "x"},
	}
	port := ln.Addr().(*net.TCPAddr).Port
	hits := ServiceProbe("127.0.0.1", rows, []int{port}, 1500, 2, nil, nil)
	if len(hits) != 1 || hits[0].Service != "ssh" || hits[0].Product != "OpenSSH" {
		t.Fatalf("SSH banner 应命中: %+v", hits)
	}
	if hits[0].Version != "8.9" {
		t.Fatalf("版本应为指纹自带版本: %+v", hits[0])
	}
}

func TestServiceProbeNoBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			time.Sleep(300 * time.Millisecond) // 不发 banner
			conn.Close()
		}
	}()

	rows := []intel.ServiceFPRow{{Service: "ssh", Pattern: `^SSH-`, Product: "OpenSSH"}}
	port := ln.Addr().(*net.TCPAddr).Port
	hits := ServiceProbe("127.0.0.1", rows, []int{port}, 200, 1, nil, nil)
	if len(hits) != 0 {
		t.Fatalf("无 banner 不应命中: %+v", hits)
	}
}

func TestServiceProbeCancel(t *testing.T) {
	rows := []intel.ServiceFPRow{{Service: "s", Pattern: `^x`, Product: "p"}}
	// race 提示：cancel 回调在 worker goroutine 内并发调用，计数须原子
	var calls atomic.Int64
	hits := ServiceProbe("127.0.0.1", rows, DefaultProbePorts, 100, 4, nil, func() bool {
		calls.Add(1)
		return calls.Load() > 21
	})
	_ = hits // 取消路径不 panic 即可
}
