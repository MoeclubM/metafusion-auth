package store

import (
	"context"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 退役键 site_name：站点名由前端构建期文案决定，账号服务里这个设置没有消费方。
// 三条口径一起钉住：写入被明确拒绝（不是静默成功）、被拒的写不落库、
// 读取面（GET /api/admin/settings 与 PublicSettings 共用的 Settings）不再回传它——
// 包括老实例可能留下的存量行，否则管理台会显示一个改不了也不生效的设置项。
func TestInstanceSettingsRetireSiteName(t *testing.T) {
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
	cleanupRow := func() {
		if _, err := db.ExecContext(context.Background(), "DELETE FROM auth.instance_settings WHERE key=$1", "site_name"); err != nil {
			t.Errorf("清理 site_name 存量行: %v", err)
		}
	}
	t.Cleanup(cleanupRow)
	cleanupRow()

	actor := &User{ID: "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f", Username: "settings-ops", Permissions: []string{"auth.settings.manage"}}
	err = s.UpdateSettings(ctx, map[string]any{"site_name": "MyInstance"}, actor)
	if err == nil || !strings.Contains(err.Error(), "invalid_setting: site_name") {
		t.Fatalf("退役键必须被明确拒绝（invalid_setting: site_name），实际 %v", err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM auth.instance_settings WHERE key=$1", "site_name").Scan(&rows); err != nil {
		t.Fatalf("查 site_name 行: %v", err)
	}
	if rows != 0 {
		t.Fatalf("被拒的写不该落库，实际 %d 行", rows)
	}

	all, err := s.Settings(ctx)
	if err != nil {
		t.Fatalf("读实例设置: %v", err)
	}
	if v, ok := all["site_name"]; ok {
		t.Fatalf("退役键不该出现在读取面：%v", v)
	}
	if _, ok := all[SettingRegistrationEnabled]; !ok {
		t.Fatalf("已知键必须照旧回传（不能把整张读面清空）：%v", all)
	}

	// 存量行（老实例真写过）同样不回传：库里有行不等于这个设置还在。
	if _, err := db.ExecContext(ctx, "INSERT INTO auth.instance_settings(key, value) VALUES($1, $2::jsonb)", "site_name", `"legacy"`); err != nil {
		t.Fatalf("插入存量行: %v", err)
	}
	all, err = s.Settings(ctx)
	if err != nil {
		t.Fatalf("读实例设置: %v", err)
	}
	if v, ok := all["site_name"]; ok {
		t.Fatalf("退役键的存量行不该回传：%v", v)
	}

	// 未知键（从未见过的名字）同样是被拒绝的写，口径一致。
	if err := s.UpdateSettings(ctx, map[string]any{"site_tagline": "hi"}, actor); err == nil || !strings.Contains(err.Error(), "invalid_setting: site_tagline") {
		t.Fatalf("未知键应 invalid_setting，实际 %v", err)
	}
}
