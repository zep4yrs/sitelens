package server

// 本文件实现 BT-03「批量完成通知（webhook）」：把批量任务结果 POST 成 JSON。
// 纯函数、无状态；URL 来源由 Lead 接线决定（本任务不改 config：
// 建议 env SLENS_BATCH_WEBHOOK，或在 config 里新增字段后传入 cfgURL）。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// batchWebhookTimeout webhook 单次请求超时（任务口径 3s）。
// 包级 var 便于测试缩短，避免每轮真等 3s。
var batchWebhookTimeout = 3 * time.Second

// webhookUserAgent 自报 UA（与 httpx 客户端一致，方便目标侧识别来源）。
const webhookUserAgent = "SiteLens/3.0.0 (+https://cnb.cool/feng-qiao/sitelens)"

// NotifyBatch 向配置的 webhook 地址 POST 一条 JSON 事件（批量完成/失败通知）。
//
//   - cfgURL 为空白：未配置 webhook → 直接返回 nil（不作为错误）；
//   - payload 为 nil：发送空 JSON 对象 {}（始终是合法 JSON 请求体）；
//   - 非 2xx：返回错误（带状态码）；网络/超时/编码错误原样带出；
//   - 3s 超时、不重试（重试节奏由调用方决定，避免拖慢批量收尾）。
//
// 接线说明（Lead 在 runBatch 收尾处调用，本文件不改 server.go）：
//
//	非取消完成时：
//	  _ = NotifyBatch(webhookURL, map[string]any{
//	      "event": "batch.done", "job_id": jobID, "total": len(items),
//	      "done": ..., "failed": ..., "cancelled": false,
//	      "tag": ..., "rows": rows,
//	  })
//	取消时 event="batch.cancelled"（仍可通知，便于前端/值班感知）。
func NotifyBatch(cfgURL string, payload map[string]any) error {
	u := strings.TrimSpace(cfgURL)
	if u == "" {
		return nil // 未配置 webhook：静默跳过（不算失败）
	}
	if payload == nil {
		payload = map[string]any{}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook 载荷编码失败：%w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook 地址非法：%w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", webhookUserAgent)

	timeout := batchWebhookTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook 请求失败：%w", err)
	}
	defer resp.Body.Close()
	// 排空响应体（有上限）以便复用连接；通知响应通常很小。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook 返回非 2xx：%d", resp.StatusCode)
	}
	return nil
}
