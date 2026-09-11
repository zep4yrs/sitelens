package nuclei

import "testing"

const tcpTPL = `id: redis-detect-test
info:
  name: Redis Detection
  severity: medium
  tags: network,redis
tcp:
  - inputs:
      - data: "PING\r\n"
    port: 6379
    matchers:
      - type: word
        words:
          - "+PONG"
`

const dnsTPL = `id: txt-detect-test
info:
  name: TXT Record Detect
  severity: info
dns:
  - name: "{{FQDN}}"
    type: TXT
    matchers:
      - type: word
        words:
          - "site-verification"
`

const sslTPL = `id: ssl-issuer-test
info:
  name: SSL Issuer Detect
  severity: low
ssl:
  - address: "{{Hostname}}:443"
    matchers:
      - type: word
        words:
          - "Let's Encrypt"
`

const httpTPL = `id: http-plain-test
info:
  name: Plain HTTP
  severity: low
http:
  - path:
      - "{{BaseURL}}/x"
    matchers:
      - type: word
        words: ["hi"]
`

func TestConvertNetworkTCP(t *testing.T) {
	nc := ConvertNetwork([]byte(tcpTPL))
	if nc == nil {
		t.Fatal("tcp 模板应准入")
	}
	if nc.Proto != "tcp" || nc.Port != 6379 || nc.Sev != "medium" {
		t.Errorf("投影不对: %+v", nc)
	}
	if len(nc.Payloads) != 1 || string(nc.Payloads[0]) != "PING\r\n" {
		t.Errorf("payload 解析不对: %q", nc.Payloads)
	}
	hit, sig := nc.MatchNetResponse("+PONG\r\n")
	if !hit || sig == "" {
		t.Errorf("+PONG 应命中: %v %q", hit, sig)
	}
	if hit, _ := nc.MatchNetResponse("-ERR unknown"); hit {
		t.Errorf("-ERR 不应命中")
	}
}

func TestConvertNetworkTCPHex(t *testing.T) {
	tpl := `id: hex-test
info:
  name: Hex Probe
  severity: low
tcp:
  - inputs:
      - hex: "0000002a"
    matchers:
      - type: binary
        words:
          - "41414141"
`
	nc := ConvertNetwork([]byte(tpl))
	if nc == nil {
		t.Fatal("hex tcp 模板应准入")
	}
	if len(nc.Payloads) != 1 || string(nc.Payloads[0]) != "\x00\x00\x00*" {
		t.Errorf("hex payload 不对: %v", nc.Payloads)
	}
	if hit, _ := nc.MatchNetResponse("junkAAAAAjunk"); !hit {
		t.Errorf("二进制 AAAA 应命中")
	}
}

func TestConvertNetworkDNSAndSSL(t *testing.T) {
	d := ConvertNetwork([]byte(dnsTPL))
	if d == nil || d.Proto != "dns" || d.DNSType != "TXT" {
		t.Fatalf("dns 模板投影不对: %+v", d)
	}
	if hit, _ := d.MatchNetResponse("v=spf1 site-verification=abc"); !hit {
		t.Errorf("dns 词命中失败")
	}
	s := ConvertNetwork([]byte(sslTPL))
	if s == nil || s.Proto != "ssl" {
		t.Fatalf("ssl 模板投影不对: %+v", s)
	}
	if hit, _ := s.MatchNetResponse("issuer: Let's Encrypt CA"); !hit {
		t.Errorf("ssl 词命中失败")
	}
}

func TestConvertNetworkRejects(t *testing.T) {
	if ConvertNetwork([]byte(httpTPL)) != nil {
		t.Errorf("http 模板不该走协议转换")
	}
	noMatcher := `id: tcp-nomatch
info:
  name: No Matchers
tcp:
  - inputs:
      - data: "X"
`
	if ConvertNetwork([]byte(noMatcher)) != nil {
		t.Errorf("无 matchers 的 tcp 模板应拒绝")
	}
	interact := `id: tcp-oob
info:
  name: OOB
tcp:
  - matchers:
      - type: word
        words: ["{{interactsh-url}}"]
`
	if ConvertNetwork([]byte(interact)) != nil {
		t.Errorf("interactsh 协议模板应拒绝")
	}
}

func TestMatchNetResponseDSLAndCondition(t *testing.T) {
	tpl := `id: dsl-cond-test
info:
  name: DSL And
  severity: low
tcp:
  - inputs:
      - data: "INFO\r\n"
    matchers:
      - type: word
        words: ["redis_version:"]
      - type: dsl
        dsl:
          - 'contains(response, "7.0")'
    matchers-condition: and
`
	nc := ConvertNetwork([]byte(tpl))
	if nc == nil {
		t.Fatal("应准入")
	}
	if hit, _ := nc.MatchNetResponse("redis_version:7.0.5"); !hit {
		t.Errorf("and 条件双命中应过")
	}
	if hit, _ := nc.MatchNetResponse("redis_version:6.2.1"); hit {
		t.Errorf("and 条件单命中不应过")
	}
}
