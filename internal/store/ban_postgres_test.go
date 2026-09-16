package store

import (
	"context"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 封禁的真实库回归：封禁后不能登录、既有会话与服务端令牌立即失效、解封恢复，
// 以及管理台列表带出封禁状态。未设置 AUTH_TEST_DSN 时整体跳过（与其它真库用例同约定）。
func TestBanLifecycleAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := testutil.DSN(t)
	db := testutil.Database(t)
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() { testutil.ResetAccounts(t, db) })
	s.Tokens = newTestIssuer(t)

	const pwd = "ban-test-secret-1"
	// setup=true 建首个管理员（要求账号表为空，ResetAccounts 已保证）。
	admin, err := s.CreateUser(ctx, "ban-admin", "", pwd, true, nil)
	if err != nil {
		t.Fatalf("建管理员: %v", err)
	}
	member, err := s.CreateUserWithRole(ctx, "ban-member", "", pwd, false, "user", &admin)
	if err != nil {
		t.Fatalf("建成员: %v", err)
	}

	token, _, err := s.Login(ctx, member.Username, pwd)
	if err != nil {
		t.Fatalf("封禁前登录: %v", err)
	}
	if _, err := s.Authenticate(ctx, token); err != nil {
		t.Fatalf("封禁前令牌应可用: %v", err)
	}

	banned, err := s.SetUserBanned(ctx, member.ID, true, &admin)
	if err != nil {
		t.Fatalf("封禁: %v", err)
	}
	if !banned.Banned || banned.ID != member.ID {
		t.Fatalf("返回值应是目标账号且 banned=true: %+v", banned)
	}

	// 登录被拒，且错误码与"口令错"可区分。
	if _, _, err := s.Login(ctx, member.Username, pwd); err == nil || err.Error() != "account_banned" {
		t.Fatalf("封禁后登录应 account_banned，实际 %v", err)
	}
	// 手里那张未过期的 JWT 立即失效：删库行拦不住无状态令牌，靠验签路径的封禁判定。
	if _, err := s.Authenticate(ctx, token); err == nil || err.Error() != "account_banned" {
		t.Fatalf("封禁后令牌应失效，实际 %v", err)
	}
	// 续期路径同样被拒，且保留同一错误码（前端据此提示停用而不是"重新登录"）。
	if _, _, err := s.Refresh(ctx, token); err == nil || err.Error() != "account_banned" {
		t.Fatalf("封禁后续期应 account_banned，实际 %v", err)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM auth.sessions WHERE user_id=$1", member.ID).Scan(&sessions); err != nil {
		t.Fatalf("查会话行: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("封禁应删除该用户的服务端会话，剩 %d 条", sessions)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("列出账号: %v", err)
	}
	found := false
	for _, u := range users {
		if u.ID == member.ID {
			found = true
			if !u.Banned {
				t.Fatalf("管理台列表必须带出封禁状态: %+v", u)
			}
		}
	}
	if !found {
		t.Fatal("列表漏掉被封禁的账号")
	}

	if _, err := s.SetUserBanned(ctx, member.ID, false, &admin); err != nil {
		t.Fatalf("解封: %v", err)
	}
	if _, _, err := s.Login(ctx, member.Username, pwd); err != nil {
		t.Fatalf("解封后应恢复登录: %v", err)
	}
}

// 封禁的护栏与计数口径：不能封自己、不能让实例失去最后一个可用管理员；
// 已封禁的管理员不再计入"还剩几个管理员"，否则"先封一个再封一个"就能绕过。
func TestBanGuardsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := testutil.DSN(t)
	db := testutil.Database(t)
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() { testutil.ResetAccounts(t, db) })

	const pwd = "ban-guard-secret-1"
	admin, err := s.CreateUser(ctx, "guard-admin", "", pwd, true, nil)
	if err != nil {
		t.Fatalf("建管理员: %v", err)
	}
	// 合成一个"持有账号管理权限但不是目标本人"的操作者：护栏要按目标身份判定，
	// 用同一个管理员当操作者会先撞上 cannot_ban_self，测不到最后一名管理员那条。
	ops := &User{ID: "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f", Username: "guard-ops", Permissions: []string{"auth.users.manage"}}

	if _, err := s.SetUserBanned(ctx, ops.ID, true, ops); err == nil || err.Error() != "cannot_ban_self" {
		t.Fatalf("封自己应被拒，实际 %v", err)
	}
	if _, err := s.SetUserBanned(ctx, admin.ID, true, ops); err == nil || err.Error() != "cannot_ban_sole_admin" {
		t.Fatalf("封最后一个管理员应被拒，实际 %v", err)
	}
	if _, err := s.SetUserBanned(ctx, "11111111-1111-1111-1111-111111111111", true, ops); err == nil || err.Error() != "user_not_found" {
		t.Fatalf("不存在的账号应 user_not_found，实际 %v", err)
	}
	// 成员没有 users.manage 时一律 forbidden（即便目标是别人）。
	member, err := s.CreateUserWithRole(ctx, "guard-member", "", pwd, false, "user", &admin)
	if err != nil {
		t.Fatalf("建成员: %v", err)
	}
	if _, err := s.SetUserBanned(ctx, admin.ID, true, &member); err == nil || err.Error() != "forbidden" {
		t.Fatalf("无权限应 forbidden，实际 %v", err)
	}

	second, err := s.CreateUserWithRole(ctx, "guard-admin2", "", pwd, false, "admin", ops)
	if err != nil {
		t.Fatalf("建第二个管理员: %v", err)
	}
	if _, err := s.SetUserBanned(ctx, admin.ID, true, ops); err != nil {
		t.Fatalf("有两个管理员时应能封其中一个: %v", err)
	}
	if _, err := s.SetUserBanned(ctx, second.ID, true, ops); err == nil || err.Error() != "cannot_ban_sole_admin" {
		t.Fatalf("已封禁的管理员不该计入剩余管理员，实际 %v", err)
	}
}
