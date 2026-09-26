package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 公开资料的真库回归：隐私边界（email 只给本人）、邀请计数口径、被封禁账号的展示，
// 以及"不存在 / 非 uuid"的原料都是 sql.ErrNoRows（HTTP 层据此回 404）。
// 未设置 AUTH_TEST_DSN 时跳过（与其它真库用例同约定）。
func TestPublicProfileAgainstPostgres(t *testing.T) {
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
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() { testutil.ResetAccounts(t, db) })
	s.Tokens = newTestIssuer(t)

	const pwd = "public-profile-secret-1"
	// setup=true 建首个管理员（要求账号表为空，ResetAccounts 已保证）。
	admin, err := s.CreateUser(ctx, "profile-admin", "", pwd, true, nil)
	if err != nil {
		t.Fatalf("建管理员: %v", err)
	}
	member, err := s.CreateUser(ctx, "profile-member", "member@example.test", pwd, false, &admin)
	if err != nil {
		t.Fatalf("建成员: %v", err)
	}

	// 计数口径要跑真实注册路径（consumeInvite 写 invite_uses），因此临时打开注册与邀请码强制，
	// 收尾复原这两行设置：它们是共享测试库上的全局状态。
	restoreSettings(t, db, SettingRegistrationEnabled, SettingInviteRequired)
	if err := s.UpdateSettings(ctx, map[string]any{SettingRegistrationEnabled: true, SettingInviteRequired: true}, &admin); err != nil {
		t.Fatalf("打开注册: %v", err)
	}
	codeA, err := s.CreateInvite(ctx, "公开资料回归", 2, 0, &admin)
	if err != nil {
		t.Fatalf("建邀请码 A: %v", err)
	}
	codeB, err := s.CreateInvite(ctx, "", 5, 0, &admin)
	if err != nil {
		t.Fatalf("建邀请码 B: %v", err)
	}
	invited1, _, err := s.Register(ctx, "invited-one", "", pwd, codeA.Code)
	if err != nil {
		t.Fatalf("注册 invited-one: %v", err)
	}
	if _, _, err := s.Register(ctx, "invited-two", "", pwd, codeA.Code); err != nil {
		t.Fatalf("注册 invited-two: %v", err)
	}
	invited3, _, err := s.Register(ctx, "invited-three", "", pwd, codeB.Code)
	if err != nil {
		t.Fatalf("注册 invited-three: %v", err)
	}

	// 匿名读别人：只有公开列。
	p, err := s.PublicProfile(ctx, member.ID, "")
	if err != nil {
		t.Fatalf("匿名读资料: %v", err)
	}
	if p.User.ID != member.ID || p.User.Username != "profile-member" {
		t.Fatalf("公开字段不符: %+v", p.User)
	}
	if p.User.Email != "" {
		t.Fatalf("匿名读别人的资料不得带 email，实际 %q", p.User.Email)
	}
	if p.User.Banned {
		t.Fatalf("未封禁账号不该带 banned")
	}
	if p.Stats.InvitedCount != 0 {
		t.Fatalf("没邀请过人的账号 invited_count 应为 0，实际 %d", p.Stats.InvitedCount)
	}

	// 登录的第三方（这里用被他邀请进来的人当请求者）看别人：同样拿不到 email。
	if p, err = s.PublicProfile(ctx, member.ID, invited1.ID); err != nil || p.User.Email != "" {
		t.Fatalf("登录用户读别人的资料不得带 email（err=%v）：%q", err, p.User.Email)
	}
	// 身份串不是 uuid 时按"不是本人"处理，不能因此 panic 或放行。
	if p, err = s.PublicProfile(ctx, member.ID, "not-a-uuid"); err != nil || p.User.Email != "" {
		t.Fatalf("无效身份串不得当成本人（err=%v）：%q", err, p.User.Email)
	}

	// 本人读自己：email 带出；id 的大小写/无连字符写法也必须认出是本人。
	for _, idForm := range []string{member.ID, strings.ToUpper(member.ID), strings.ReplaceAll(member.ID, "-", "")} {
		self, serr := s.PublicProfile(ctx, idForm, member.ID)
		if serr != nil {
			t.Fatalf("本人读自己 %q: %v", idForm, serr)
		}
		if self.User.ID != member.ID || self.User.Email != member.Email {
			t.Fatalf("%q 应解析到本人并带出 email，实际 id=%q email=%q", idForm, self.User.ID, self.User.Email)
		}
	}

	// invited_count：admin 用两个码拉进来 3 个人（A 码 2 个 + B 码 1 个）。
	adminView, err := s.PublicProfile(ctx, admin.ID, "")
	if err != nil {
		t.Fatalf("读管理员资料: %v", err)
	}
	if adminView.Stats.InvitedCount != 3 {
		t.Fatalf("invited_count 应为 3，实际 %d", adminView.Stats.InvitedCount)
	}
	if adminView.User.Email != "" {
		t.Fatalf("匿名读管理员的资料不得带 email")
	}
	// 吊销邀请码不回溯扣减：人已经进来了，与 InvitedMembers 的展示口径一致。
	if err := s.RevokeInvite(ctx, codeB.Code, &admin); err != nil {
		t.Fatalf("吊销邀请码 B: %v", err)
	}
	if adminView, err = s.PublicProfile(ctx, admin.ID, ""); err != nil || adminView.Stats.InvitedCount != 3 {
		t.Fatalf("吊销后 invited_count 仍应为 3（err=%v），实际 %d", err, adminView.Stats.InvitedCount)
	}

	// 被封禁的账号照样能被读到，只带 banned 标记；也不改变邀请人的计数。
	if _, err := s.SetUserBanned(ctx, invited3.ID, true, &admin); err != nil {
		t.Fatalf("封禁 invited-three: %v", err)
	}
	bannedView, err := s.PublicProfile(ctx, invited3.ID, "")
	if err != nil {
		t.Fatalf("读被封禁账号的资料: %v", err)
	}
	if !bannedView.User.Banned || bannedView.User.Username != "invited-three" {
		t.Fatalf("被封禁账号应返回资料且带 banned=true，实际 %+v", bannedView.User)
	}
	if adminView, err = s.PublicProfile(ctx, admin.ID, ""); err != nil || adminView.Stats.InvitedCount != 3 {
		t.Fatalf("受邀者被封禁不该改变邀请人的计数（err=%v），实际 %d", err, adminView.Stats.InvitedCount)
	}

	// 不存在与非法 id：一律 sql.ErrNoRows（respond 映射 404），不是别的错误。
	for _, bad := range []string{uuid.NewString(), "not-a-uuid", "  ", strings.Repeat("f", 32) + "z"} {
		if _, err := s.PublicProfile(ctx, bad, ""); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("id=%q 应回 sql.ErrNoRows，实际 %v", bad, err)
		}
	}
}

// restoreSettings 让用例改动实例设置后复原：这些键是共享测试库上的全局状态，
// 留给下一个用例就等于"上一次跑过什么决定这一次的结果"。做法与 rate_limit_policy_test 一致。
func restoreSettings(t *testing.T, db *sql.DB, keys ...string) {
	t.Helper()
	type prior struct {
		exists bool
		raw    string
	}
	before := map[string]prior{}
	for _, k := range keys {
		var raw string
		err := db.QueryRow("SELECT value::text FROM auth.instance_settings WHERE key=$1", k).Scan(&raw)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			t.Fatalf("读旧设置 %s: %v", k, err)
		default:
			before[k] = prior{exists: true, raw: raw}
		}
	}
	t.Cleanup(func() {
		for _, k := range keys {
			if before[k].exists {
				if _, err := db.Exec("UPDATE auth.instance_settings SET value=$2::jsonb WHERE key=$1", k, before[k].raw); err != nil {
					t.Errorf("恢复设置 %s: %v", k, err)
				}
				continue
			}
			if _, err := db.Exec("DELETE FROM auth.instance_settings WHERE key=$1", k); err != nil {
				t.Errorf("清理设置 %s: %v", k, err)
			}
		}
	})
}

// 自助资料的真库回归：改昵称/简介后公开读与本人读都即时可见；空串=未设置；
// 超限 400（昵称 32 / 简介 500 rune）；不存在的账号 404。
// 未设置 AUTH_TEST_DSN 时跳过。
func TestUpdateProfileAgainstPostgres(t *testing.T) {
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
	testutil.ResetAccounts(t, db)
	t.Cleanup(func() { testutil.ResetAccounts(t, db) })
	s.Tokens = newTestIssuer(t)

	const pwd = "profile-update-secret-1"
	admin, err := s.CreateUser(ctx, "profile-upd-admin", "", pwd, true, nil)
	if err != nil {
		t.Fatalf("建管理员: %v", err)
	}
	member, err := s.CreateUser(ctx, "profile-upd-member", "upd-member@example.test", pwd, false, &admin)
	if err != nil {
		t.Fatalf("建成员: %v", err)
	}

	out, err := s.UpdateProfile(ctx, member.ID, "  阿策  ", "写简介\n第二行")
	if err != nil {
		t.Fatalf("改资料: %v", err)
	}
	if out.DisplayName != "阿策" || out.Bio != "写简介\n第二行" {
		t.Fatalf("应 trim 后落库，实际 %+v", out)
	}
	// 公开读即时可见；本人读同样带出。
	if p, err := s.PublicProfile(ctx, member.ID, ""); err != nil || p.User.DisplayName != "阿策" || p.User.Bio != "写简介\n第二行" {
		t.Fatalf("公开读应即时可见（err=%v）：%+v", err, p.User)
	}
	// 清空回未设置。
	if out, err = s.UpdateProfile(ctx, member.ID, "", ""); err != nil || out.DisplayName != "" || out.Bio != "" {
		t.Fatalf("清空应回空串（err=%v）：%+v", err, out)
	}
	// 超限。
	if _, err = s.UpdateProfile(ctx, member.ID, strings.Repeat("昵", 33), ""); err == nil || err.Error() != "invalid_display_name" {
		t.Fatalf("昵称 33 字应 invalid_display_name，实际 %v", err)
	}
	if _, err = s.UpdateProfile(ctx, member.ID, "", strings.Repeat("b", 501)); err == nil || err.Error() != "invalid_bio" {
		t.Fatalf("简介 501 字应 invalid_bio，实际 %v", err)
	}
	// 不存在的账号。
	if _, err = s.UpdateProfile(ctx, uuid.NewString(), "x", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("不存在的账号应 ErrNoRows，实际 %v", err)
	}
}
