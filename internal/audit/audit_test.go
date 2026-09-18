package audit

// 脱敏与队列语义的单测：这两件事错了不会编译失败，只会安静地把口令写进审计表，
// 或者让审计反过来拖住业务请求。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// 键名黑名单必须覆盖口令/密钥/令牌/哈希四类，并且递归进嵌套结构。
func TestSanitizeChangesRedactsCredentialKeys(t *testing.T) {
	in := map[string]any{
		"password":      "hunter2",
		"new_password":  "hunter3",
		"token":         "mfp_abcdef",
		"client_secret": "s3cr3t",
		"token_hash":    "deadbeef",
		"nested":        map[string]any{"api_secret": "nope"},
		"role":          "editor",
	}
	out := SanitizeChanges(in)
	for _, key := range []string{"password", "new_password", "token", "client_secret", "token_hash"} {
		if out[key] != Redacted {
			t.Fatalf("%s 应被脱敏，实际 %v", key, out[key])
		}
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok || nested["api_secret"] != Redacted {
		t.Fatalf("嵌套结构里的凭据键应被脱敏，实际 %#v", out["nested"])
	}
	if out["role"] != "editor" {
		t.Fatalf("非敏感键不该被改动，实际 %v", out["role"])
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("摘要应可序列化：%v", err)
	}
	for _, secret := range []string{"hunter2", "hunter3", "mfp_abcdef", "s3cr3t", "deadbeef", "nope"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("序列化后的摘要仍含明文 %q：%s", secret, raw)
		}
	}
}

// email 是三层防线里最容易漏的一层：键名叫 email、值里顺手带了邮箱、以及嵌套列表里的邮箱。
func TestSanitizeChangesMasksEmails(t *testing.T) {
	in := map[string]any{
		"email":          "jane.doe@example.com",
		"attempted":      "tried jane.doe@example.com just now",
		"target_emails":  []any{"a@b.co", "plain"},
		"target_emails2": []string{"c@d.co"},
	}
	out := SanitizeChanges(in)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if strings.Contains(string(raw), "@example.com") && strings.Contains(string(raw), "jane.doe") {
		t.Fatalf("完整邮箱不该进摘要：%s", raw)
	}
	if out["email"] != "j***@example.com" {
		t.Fatalf("email 键应按遮罩形式落库，实际 %v", out["email"])
	}
	if !strings.Contains(out["attempted"].(string), "j***@example.com") {
		t.Fatalf("值里出现的邮箱也要遮罩，实际 %v", out["attempted"])
	}
	first := out["target_emails"].([]any)[0].(string)
	if first != "a***@b.co" {
		t.Fatalf("列表里的邮箱也要遮罩，实际 %v", first)
	}
}

// MaskSecret 只留给准凭据（邀请码、一次性码）：保留前 4 位供人工比对。
func TestMaskSecretKeepsFourRunes(t *testing.T) {
	if got := MaskSecret("abcd1234"); got != "abcd…" {
		t.Fatalf("MaskSecret = %q", got)
	}
	if got := MaskSecret("ab"); got != "**" {
		t.Fatalf("短值应整串打码，实际 %q", got)
	}
}

// 单值截断与整份摘要超限的兜底：库里永远要留一条可读的痕迹，不能是半截 JSON。
func TestSanitizeChangesTruncatesLongContent(t *testing.T) {
	long := strings.Repeat("值", 600)
	out := SanitizeChanges(map[string]any{"note": long})
	got := out["note"].(string)
	if len([]rune(got)) > maxValueLen+1 {
		t.Fatalf("单值应按 rune 截断到 %d，实际 %d", maxValueLen, len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("截断后应有省略号：%q", got[len(got)-8:])
	}
	big := map[string]any{}
	for i := 0; i < 200; i++ {
		big[string(rune('a'+i%26))+strings.Repeat("k", i%5)] = strings.Repeat("x", 200)
	}
	encoded, err := marshalChanges(SanitizeChanges(big))
	if err != nil {
		t.Fatalf("超限摘要仍应可序列化：%v", err)
	}
	if !strings.Contains(encoded, "_truncated") {
		t.Fatalf("超限摘要应换成截断标记，实际 %s", encoded[:80])
	}
	var marker map[string]any
	if err := json.Unmarshal([]byte(encoded), &marker); err != nil {
		t.Fatalf("截断标记应是合法 JSON：%v", err)
	}
	if _, ok := marker["_keys"]; !ok {
		t.Fatalf("截断标记应带上被丢掉的键名清单：%v", marker)
	}
}

// 队列满时 Record 必须立刻返回并计数：这条路径在业务请求的返回路径上，阻塞等于拖垮服务。
// 用例刻意不起后台 goroutine，让队列一定填满。
func TestRecordIsNonBlockingWhenQueueFull(t *testing.T) {
	r := &Recorder{service: ServiceName, jobs: make(chan job, 1)}
	r.Record(Entry{Action: "user.role_changed"})
	done := make(chan struct{})
	go func() { r.Record(Entry{Action: "user.role_changed"}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("队列满时 Record 阻塞了")
	}
	if r.Dropped() != 1 {
		t.Fatalf("队列满应计一次丢弃，实际 %d", r.Dropped())
	}
}

// db 为 nil 时（不建库的用例）写入降级成计数：不落库、不报错，也不假装写过。
func TestRecorderFlushAndCloseAreSafeWithoutDB(t *testing.T) {
	r := NewRecorder(nil, ServiceName)
	r.Record(Entry{Action: "settings.updated", Changes: map[string]any{"a": 1}})
	if err := r.Flush(contextWithTimeout(t)); err != nil {
		t.Fatalf("Flush 应等到队列排空：%v", err)
	}
	r.Close()
	r.Close()
	if r.Written() != 1 {
		t.Fatalf("应记下 1 条写入，实际 %d", r.Written())
	}
}

// prepare 的默认值：id、时间、服务名、结果、长度上限。
func TestPrepareFillsDefaultsAndTruncates(t *testing.T) {
	r := NewRecorder(nil, ServiceName)
	entry := r.prepare(Entry{Action: "x.y", ActorUserAgent: strings.Repeat("u", 900)})
	if entry.ID == "" || entry.OccurredAt.IsZero() {
		t.Fatalf("id 与时间应补默认值：%#v", entry)
	}
	if entry.Service != ServiceName || entry.Result != ResultSuccess {
		t.Fatalf("服务名与结果应补默认值：%#v", entry)
	}
	if len([]rune(entry.ActorUserAgent)) > maxUserAgent+1 {
		t.Fatalf("UA 应截断到 %d，实际 %d", maxUserAgent, len([]rune(entry.ActorUserAgent)))
	}
}

// MaskEmail 的边界：没有 @、@ 在首尾时按原样截断返回，不能 panic，也不能把整串吃掉。
func TestMaskEmailEdgeCases(t *testing.T) {
	for _, in := range []string{"no-at-sign", "@example.com", "trailing@"} {
		if got := MaskEmail(in); got == "" {
			t.Fatalf("MaskEmail(%q) 不该返回空串", in)
		}
	}
	if got := MaskEmail("jane@example.com"); got != "j***@example.com" {
		t.Fatalf("MaskEmail = %q", got)
	}
}

// contextWithTimeout 是 Flush 用例的上下文：正常瞬间返回，异常时 5 秒兜底。
func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
