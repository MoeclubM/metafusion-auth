package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 没有数据库的桩实例必须按默认策略回答：限流是"额外的拒绝条件"，读不到配置不能变成放开。
func TestRateLimitPolicyDefaultsWithoutDatabase(t *testing.T) {
	enabled, perMinute := (&Store{}).RateLimitPolicy(context.Background())
	if !enabled || perMinute != DefaultRateLimitPerMinute {
		t.Fatalf("无库时应是默认策略 (%v, %d)，实际 (%v, %d)", true, DefaultRateLimitPerMinute, enabled, perMinute)
	}
}

// 限流设置接线后的口径：默认 = 接线前的强制值；改成 N 立即生效；关掉即不限流；
// 写设置会作废缓存（否则管理台改完要等 TTL 才生效，用户会以为没保存）。
// 用例读写的是共享测试库的 instance_settings，退出前把两行恢复原状。
func TestRateLimitPolicyFollowsSettingsAgainstPostgres(t *testing.T) {
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

	type prior struct {
		exists bool
		raw    string
	}
	load := func(key string) prior {
		t.Helper()
		var raw string
		err := db.QueryRowContext(ctx, "SELECT value::text FROM auth.instance_settings WHERE key=$1", key).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return prior{}
		}
		if err != nil {
			t.Fatalf("读旧设置 %s: %v", key, err)
		}
		return prior{exists: true, raw: raw}
	}
	keys := []string{SettingAuthRateLimitEnabled, SettingRateLimitPerMinute}
	before := map[string]prior{}
	for _, k := range keys {
		before[k] = load(k)
	}
	t.Cleanup(func() {
		for _, k := range keys {
			if before[k].exists {
				_, _ = db.ExecContext(context.Background(), "UPDATE auth.instance_settings SET value=$2::jsonb WHERE key=$1", k, before[k].raw)
				continue
			}
			_, _ = db.ExecContext(context.Background(), "DELETE FROM auth.instance_settings WHERE key=$1", k)
		}
	})

	actor := &User{ID: "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f", Username: "policy-ops", Permissions: []string{"auth.settings.manage"}}
	// 先清掉两行，让"默认值"这条断言不被历史设置影响。
	for _, k := range keys {
		if _, err := db.ExecContext(ctx, "DELETE FROM auth.instance_settings WHERE key=$1", k); err != nil {
			t.Fatalf("清理设置 %s: %v", k, err)
		}
	}
	s.invalidateRateLimitCache()
	if enabled, n := s.RateLimitPolicy(ctx); !enabled || n != DefaultRateLimitPerMinute {
		t.Fatalf("缺省应 (%v, %d)，实际 (%v, %d)", true, DefaultRateLimitPerMinute, enabled, n)
	}

	if err := s.UpdateSettings(ctx, map[string]any{SettingAuthRateLimitEnabled: false}, actor); err != nil {
		t.Fatalf("关闭限流: %v", err)
	}
	if enabled, n := s.RateLimitPolicy(ctx); enabled || n != DefaultRateLimitPerMinute {
		t.Fatalf("关闭后应不限流（速率仍回报默认值），实际 (%v, %d)", enabled, n)
	}

	if err := s.UpdateSettings(ctx, map[string]any{SettingAuthRateLimitEnabled: true, SettingRateLimitPerMinute: 999}, actor); err != nil {
		t.Fatalf("改速率: %v", err)
	}
	if enabled, n := s.RateLimitPolicy(ctx); !enabled || n != 999 {
		t.Fatalf("改速率后应立即生效，实际 (%v, %d)", enabled, n)
	}
	// 公开设置与策略必须同源：管理台显示 999 而实际按别的数限流，就是接线前的那个空承诺。
	public, err := s.PublicSettings(ctx)
	if err != nil {
		t.Fatalf("读公开设置: %v", err)
	}
	if got, ok := toInt(public["auth_rate_limit_per_minute"]); !ok || got != 999 {
		t.Fatalf("公开设置应报 999，实际 %v", public["auth_rate_limit_per_minute"])
	}

	// 缓存已在上一次读取时写入 TTL：这里紧接着改，必须立刻看到新值（UpdateSettings 作废缓存）。
	if err := s.UpdateSettings(ctx, map[string]any{SettingRateLimitPerMinute: 777}, actor); err != nil {
		t.Fatalf("再改速率: %v", err)
	}
	if _, n := s.RateLimitPolicy(ctx); n != 777 {
		t.Fatalf("写设置后缓存应立刻失效，实际 %d（缓存把改动拖到 TTL 之后）", n)
	}
}
