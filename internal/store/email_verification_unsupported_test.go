package store

import (
	"context"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// require_email_verification 的三方矛盾（注释说恒为 false、管理面可写 true、实现里没有强制点、
// 登录页据此显示"需要邮箱验证"）按"暂不支持"收敛：读面一律按生效值 false 回答，
// 写面只接受 false，true 明确拒绝（unsupported_setting，与"未知键"的 invalid_setting 区分）。
func TestRequireEmailVerificationIsUnsupported(t *testing.T) {
	ctx := context.Background()
	db := testutil.Database(t)
	s, err := Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	const key = SettingRequireEmailVerify
	cleanupRow := func() {
		if _, err := db.ExecContext(context.Background(), "DELETE FROM auth.instance_settings WHERE key=$1", key); err != nil {
			t.Errorf("清理 %s 存量行: %v", key, err)
		}
	}
	t.Cleanup(cleanupRow)
	cleanupRow()

	actor := &User{ID: "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f1", Username: "settings-ops", Permissions: []string{"auth.settings.manage"}}
	if err := s.UpdateSettings(ctx, map[string]any{key: true}, actor); err == nil || !strings.Contains(err.Error(), "unsupported_setting: "+key) {
		t.Fatalf("打开一个没有强制点的开关必须被明确拒绝，实际 %v", err)
	}
	var stored *bool
	if err := db.QueryRowContext(ctx, "SELECT (value::text)::boolean FROM auth.instance_settings WHERE key=$1", key).Scan(&stored); err != nil && err.Error() != "sql: no rows in result set" {
		t.Fatalf("查 %s 行: %v", key, err)
	}
	if stored != nil && *stored {
		t.Fatal("被拒绝的写不该落库成 true")
	}

	// 存量 true 行（老实例真写过）也必须按生效值 false 回答：
	// 管理台与登录页读到的都得是"这一项没有生效"，而不是一个看起来打开的开关。
	if _, err := db.ExecContext(ctx, "INSERT INTO auth.instance_settings(key, value) VALUES($1, 'true'::jsonb) ON CONFLICT (key) DO UPDATE SET value=excluded.value", key); err != nil {
		t.Fatalf("插入存量行: %v", err)
	}
	all, err := s.Settings(ctx)
	if err != nil {
		t.Fatalf("读实例设置: %v", err)
	}
	if v, _ := all[key].(bool); v {
		t.Fatalf("存量 true 行不该回传为 true：%v", all[key])
	}
	public, err := s.PublicSettings(ctx)
	if err != nil {
		t.Fatalf("读公开设置: %v", err)
	}
	if v, _ := public[key].(bool); v {
		t.Fatalf("公开面同样只能是 false：%v", public[key])
	}

	// false 照旧接受（幂等回写整份设置的管理客户端不该被挡住）。
	if err := s.UpdateSettings(ctx, map[string]any{key: false}, actor); err != nil {
		t.Fatalf("写入 false 应被接受：%v", err)
	}
}
