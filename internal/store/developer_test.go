package store

// 开发者中心的存储侧回归：归属边界（别人的应用按不存在处理）、平台自有应用的自动核验、
// 配额、以及"开发者路径写不了管理面字段"。
//
// 需要真实库的部分未设置 AUTH_TEST_DSN 时跳过；跑法见 README（-p 1 串行）。

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

func devStrPtr(s string) *string { return &s }

func devStrsPtr(v ...string) *[]string { return &v }

func TestDeveloperAppProjection(t *testing.T) {
	// 自有平台：trusted 即第一方，核验状态由 trusted 派生（种子行未必写了 verified）。
	first := DeveloperAppOf(OAuthClient{ID: "metafusion-catalog", Name: "目录", Trusted: true, SecretHash: ""})
	if !first.FirstParty || !first.Verified {
		t.Fatalf("trusted 客户端应为自有平台且已核验: %+v", first)
	}
	if first.HasSecret {
		t.Fatal("无密钥的第一方不应报 has_secret")
	}
	// 第三方：first_party 必须为 false，verified 只看库里的列。
	third := DeveloperAppOf(OAuthClient{ID: "mfc-abc", Name: "第三方", Verified: false, SecretHash: "$2a$10$x"})
	if third.FirstParty || third.Verified {
		t.Fatalf("未核验的第三方不应是自有平台或已核验: %+v", third)
	}
	if !third.HasSecret {
		t.Fatal("有密钥哈希的应用应报 has_secret")
	}
}

// TestDeveloperUpdateRejectsManagedFields 覆盖"管理面字段在开发者路径上被明确拒绝"。
// 这条判定发生在写库之前，因此不需要数据库。
func TestDeveloperUpdateRejectsManagedFields(t *testing.T) {
	s := &Store{}
	actor := &User{ID: "11111111-1111-1111-1111-111111111111"}
	trusted, verified, disabled := true, true, true
	for name, in := range map[string]OAuthClientInput{
		"trusted":  {Trusted: &trusted},
		"verified": {Verified: &verified},
		"disabled": {Disabled: &disabled},
	} {
		_, err := s.updateOAuthClient(context.Background(), "mfc-abc", in, actor, false, nil)
		if err == nil || !strings.HasPrefix(err.Error(), "invalid_field") {
			t.Fatalf("%s 字段必须被拒绝，实际 err=%v", name, err)
		}
	}
}

// TestDeveloperCenterAgainstPostgres 走一遍真实库上的自助登记：归属隔离、平台清单、核验与删除。
func TestDeveloperCenterAgainstPostgres(t *testing.T) {
	dsn := testutil.DSN(t)
	db := testutil.Database(t)
	ctx := context.Background()

	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	// 首管要求空库：先清账号（串行跑时上游包会留下会话行），收尾清掉本次建的客户端与账号。
	testutil.ResetAccounts(t, db)
	var createdClients []string
	t.Cleanup(func() {
		for _, id := range createdClients {
			_, _ = db.Exec("DELETE FROM auth.oauth_clients WHERE id=$1", id)
		}
		testutil.ResetAccounts(t, db)
	})

	admin, err := s.CreateUser(ctx, "dev-admin", "", "developer-center-secret", true, nil)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	member, err := s.CreateUser(ctx, "dev-member", "", "developer-center-secret", false, &admin)
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	other, err := s.CreateUser(ctx, "dev-other", "", "developer-center-secret", false, &admin)
	if err != nil {
		t.Fatalf("create other: %v", err)
	}

	// 自助登记：归属调用者，且 trusted/disabled/verified 三个管理面列必须是 false。
	app, secret, err := s.CreateDeveloperApp(ctx, DeveloperAppInput{
		Name:         devStrPtr("示例第三方站点"),
		Description:  devStrPtr("读取基本资料与邮箱"),
		HomepageURL:  devStrPtr("https://app.example"),
		RedirectURIs: devStrsPtr("https://app.example/callback"),
		Scopes:       devStrsPtr("openid", "email"),
	}, &member)
	if err != nil {
		t.Fatalf("create developer app: %v", err)
	}
	createdClients = append(createdClients, app.ID)
	if !strings.HasPrefix(app.ID, "mfc-") || len(secret) != 43 {
		t.Fatalf("client_id/密钥形状不符: id=%q secret_len=%d", app.ID, len(secret))
	}
	if app.OwnerID != member.ID || app.FirstParty || app.Verified || app.Disabled || !app.HasSecret {
		t.Fatalf("自助登记的应用投影不符: %+v", app)
	}
	if strings.Join(app.Scopes, " ") != "openid email" {
		t.Fatalf("scope 应按请求落库: %v", app.Scopes)
	}
	var trusted, disabled, verified bool
	var ownerID string
	if err := db.QueryRow("SELECT trusted, disabled, verified, COALESCE(owner_user_id::text,'') FROM auth.oauth_clients WHERE id=$1", app.ID).Scan(&trusted, &disabled, &verified, &ownerID); err != nil {
		t.Fatalf("读回客户端: %v", err)
	}
	if trusted || disabled || verified {
		t.Fatalf("开发者路径不得写入管理面字段: trusted=%v disabled=%v verified=%v", trusted, disabled, verified)
	}
	if ownerID != member.ID {
		t.Fatalf("归属未落库: %q != %q", ownerID, member.ID)
	}

	// 归属隔离：别人的应用一律按"不存在"处理，读/改/轮换/删四条路径同一口径。
	if _, err := s.GetDeveloperApp(ctx, app.ID, &member); err != nil {
		t.Fatalf("本人应能读自己的应用: %v", err)
	}
	for name, err := range map[string]error{
		"读": func() error { _, err := s.GetDeveloperApp(ctx, app.ID, &other); return err }(),
		"改": func() error {
			_, err := s.UpdateDeveloperApp(ctx, app.ID, DeveloperAppInput{Name: devStrPtr("被改名")}, &other)
			return err
		}(),
		"轮换": func() error { _, _, err := s.RotateDeveloperAppSecret(ctx, app.ID, &other); return err }(),
		"删":  s.DeleteDeveloperApp(ctx, app.ID, &other),
	} {
		if err == nil || err.Error() != "client_not_found" {
			t.Fatalf("%s别人的应用应报 client_not_found，实际 err=%v", name, err)
		}
	}
	var name string
	if err := db.QueryRow("SELECT name FROM auth.oauth_clients WHERE id=$1", app.ID).Scan(&name); err != nil || name != "示例第三方站点" {
		t.Fatalf("越权改名被拒后名字不应变化: name=%q err=%v", name, err)
	}

	// 本人的合法改动：改名 / 简介 / 主页都能落库；非法主页必须被拒。
	if app, err = s.UpdateDeveloperApp(ctx, app.ID, DeveloperAppInput{Name: devStrPtr("示例站点（改名）"), HomepageURL: devStrPtr("https://new.example")}, &member); err != nil {
		t.Fatalf("本人改名: %v", err)
	}
	if app.Name != "示例站点（改名）" || app.HomepageURL != "https://new.example" {
		t.Fatalf("更新未生效: %+v", app)
	}
	if _, err = s.UpdateDeveloperApp(ctx, app.ID, DeveloperAppInput{HomepageURL: devStrPtr("javascript:alert(1)")}, &member); err == nil || !strings.HasPrefix(err.Error(), "invalid_homepage_url") {
		t.Fatalf("非法主页必须被拒，实际 err=%v", err)
	}

	// 核验只有管理员能做；核验后 developer 投影与库里的列都要变。
	if _, err = s.SetDeveloperAppVerified(ctx, app.ID, true, &member); err == nil || err.Error() != "forbidden" {
		t.Fatalf("普通成员核验应 403，实际 err=%v", err)
	}
	if app, err = s.SetDeveloperAppVerified(ctx, app.ID, true, &admin); err != nil {
		t.Fatalf("管理员核验: %v", err)
	}
	if !app.Verified || app.FirstParty {
		t.Fatalf("核验后应已核验但仍非自有平台: %+v", app)
	}

	// 列表：成员只看得到自己的应用；管理员看得到全部（含别人登记的）。
	mine, err := s.ListDeveloperApps(ctx, &member)
	if err != nil || len(mine) != 1 || mine[0].ID != app.ID {
		t.Fatalf("成员应只看到自己的 1 个应用: %+v err=%v", mine, err)
	}
	all, err := s.ListDeveloperApps(ctx, &admin)
	if err != nil {
		t.Fatalf("管理员列表: %v", err)
	}
	seen := false
	for _, item := range all {
		if item.ID == app.ID {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("管理员应看到成员登记的应用: %+v", all)
	}

	// 自有平台清单：三个种子客户端都在，且都是"免同意 + 已核验 + 无归属"。
	platforms, err := s.ListPlatformApps(ctx)
	if err != nil {
		t.Fatalf("平台清单: %v", err)
	}
	found := map[string]bool{}
	for _, item := range platforms {
		if !item.FirstParty || !item.Verified || item.OwnerID != "" {
			t.Fatalf("平台清单里混进了非自有平台: %+v", item)
		}
		found[item.ID] = true
	}
	for _, id := range seededClientIDs {
		if !found[id] {
			t.Fatalf("平台清单缺少种子客户端 %s: %+v", id, platforms)
		}
	}
	for _, item := range platforms {
		if item.ID == app.ID {
			t.Fatalf("自助登记的应用不得出现在平台清单里: %+v", item)
		}
	}

	// 轮换密钥：明文只返回一次，旧密钥立即失效。
	before, err := s.GetOAuthClient(ctx, app.ID)
	if err != nil {
		t.Fatalf("读轮换前的客户端: %v", err)
	}
	rotated, nextSecret, err := s.RotateDeveloperAppSecret(ctx, app.ID, &member)
	if err != nil {
		t.Fatalf("轮换: %v", err)
	}
	if nextSecret == secret || rotated.ID != app.ID {
		t.Fatalf("轮换应换出新的明文密钥: %q", nextSecret)
	}
	after, err := s.GetOAuthClient(ctx, app.ID)
	if err != nil {
		t.Fatalf("读轮换后的客户端: %v", err)
	}
	if VerifyClientSecret(after.SecretHash, secret) || !VerifyClientSecret(after.SecretHash, nextSecret) {
		t.Fatalf("旧密钥应失效、新密钥应可用（before=%q）", before.SecretHash)
	}

	// 配额：给另一个账号直接灌满 MaxDeveloperAppsPerUser 行，再自助登记必须被拒。
	for i := 0; i < MaxDeveloperAppsPerUser; i++ {
		id := fmt.Sprintf("mfc-quota-%02d", i)
		if _, err := db.Exec("INSERT INTO auth.oauth_clients(id, secret_hash, name, redirect_uris, scopes, trusted, disabled, verified, owner_user_id) VALUES($1,'',$2,'{}','{openid}',false,false,false,$3)", id, "配额占位", other.ID); err != nil {
			t.Fatalf("灌配额行 %d: %v", i, err)
		}
		createdClients = append(createdClients, id)
	}
	if _, _, err = s.CreateDeveloperApp(ctx, DeveloperAppInput{Name: devStrPtr("超额应用"), RedirectURIs: devStrsPtr("https://over.example/cb")}, &other); err == nil || err.Error() != "app_quota_exceeded" {
		t.Fatalf("配额用尽后必须拒绝，实际 err=%v", err)
	}

	// 删除：本人删掉自己的应用后读不到，库里也没有了。
	if err := s.DeleteDeveloperApp(ctx, app.ID, &member); err != nil {
		t.Fatalf("删除: %v", err)
	}
	if _, err := s.GetOAuthClient(ctx, app.ID); err == nil {
		t.Fatal("删除后不应还能读到客户端")
	}
}
