package store

import (
	"context"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 用户自助授权管理：列表要同时看到"生效中的令牌"与"授权过但已过期"的应用，
// 撤回只作用于本人（别人的令牌必须完好），并留下审计。未设置 AUTH_TEST_DSN 时跳过。
func TestOAuthGrantsAgainstPostgres(t *testing.T) {
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

	const pwd = "grant-test-secret-1"
	const callback = "https://client.example/auth/callback"
	admin, err := s.CreateUser(ctx, "grant-admin", "", pwd, true, nil)
	if err != nil {
		t.Fatalf("建管理员: %v", err)
	}
	owner, err := s.CreateUser(ctx, "grant-owner", "", pwd, false, &admin)
	if err != nil {
		t.Fatalf("建授权人: %v", err)
	}
	other, err := s.CreateUser(ctx, "grant-other", "", pwd, false, &admin)
	if err != nil {
		t.Fatalf("建另一个人: %v", err)
	}

	clientID := "mfc-grant-" + strings.ReplaceAll(newUUID(), "-", "")[:10]
	if _, _, err := s.CreateOAuthClient(ctx, OAuthClientInput{
		ID:           clientID,
		Name:         strPtr("授权测试应用"),
		RedirectURIs: &[]string{callback},
		Scopes:       &[]string{"openid", "profile"},
	}, &admin); err != nil {
		t.Fatalf("建客户端: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_audit WHERE client_id=$1", clientID)
		_, _ = s.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_tokens WHERE client_id=$1", clientID)
		_, _ = s.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_codes WHERE client_id=$1", clientID)
		_, _ = s.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_clients WHERE id=$1", clientID)
	})
	// 明文密钥只在创建与轮换时返回一次：这里轮换一次取回，供后面的换码使用。
	_, secret, err := s.RotateOAuthClientSecret(ctx, clientID, &admin)
	if err != nil {
		t.Fatalf("轮换密钥取明文: %v", err)
	}

	issue := func(u User) OAuthGrant {
		t.Helper()
		if err := s.RecordOAuthAudit(ctx, OAuthAuditEntry{
			ActorID: u.ID, SubjectID: u.ID, ClientID: clientID,
			Action: OAuthActionConsentAllow, Scopes: []string{"openid", "profile"},
		}); err != nil {
			t.Fatalf("记录同意审计: %v", err)
		}
		code, _, err := s.CreateOAuthCode(ctx, clientID, u.ID, callback, "openid profile", "", "")
		if err != nil {
			t.Fatalf("发授权码: %v", err)
		}
		g, err := s.ExchangeOAuthCode(ctx, clientID, secret, code, callback, "")
		if err != nil {
			t.Fatalf("换码: %v", err)
		}
		return g
	}
	ownerGrant := issue(owner)
	otherGrant := issue(other)

	items, err := s.ListOAuthGrants(ctx, owner.ID)
	if err != nil {
		t.Fatalf("列出授权: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("授权人应只看到自己那一个应用，实际 %d 条: %+v", len(items), items)
	}
	got := items[0]
	if got.ClientID != clientID || got.Name != "授权测试应用" || !got.Active {
		t.Fatalf("列表项不符: %+v", got)
	}
	if !containsStr(got.Scopes, "openid") || !containsStr(got.Scopes, "profile") {
		t.Fatalf("scope 应从生效令牌聚合出来: %+v", got.Scopes)
	}
	if got.LastAuthorizedAt == "" || got.ExpiresAt == "" {
		t.Fatalf("应带最近授权时间与令牌到期时间: %+v", got)
	}

	n, err := s.RevokeOwnOAuthGrant(ctx, owner.ID, clientID)
	if err != nil {
		t.Fatalf("自助撤回: %v", err)
	}
	if n < 1 {
		t.Fatalf("应至少删掉一条令牌，实际 %d", n)
	}
	if _, err := s.UserFromOAuthToken(ctx, ownerGrant.Token); err == nil {
		t.Fatal("撤回后本人的第三方令牌必须失效")
	}
	if _, err := s.UserFromOAuthToken(ctx, otherGrant.Token); err != nil {
		t.Fatalf("撤回只应作用于本人，别人的令牌被误删: %v", err)
	}

	// 撤回后仍应在列表里（有同意审计），但不再是"生效中"：用户要能看到"曾经授权过"。
	items, err = s.ListOAuthGrants(ctx, owner.ID)
	if err != nil {
		t.Fatalf("撤回后再列: %v", err)
	}
	if len(items) != 1 || items[0].Active {
		t.Fatalf("撤回后应显示为已失效的一条记录: %+v", items)
	}
	if items[0].LastAuthorizedAt == "" {
		t.Fatal("撤回不该抹掉最近授权时间（它来自审计）")
	}

	audits, err := s.ListOAuthAudits(ctx, clientID, 50)
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	revoked := 0
	for _, a := range audits {
		if a.Action == OAuthActionTokensRevoked && a.SubjectID == owner.ID {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("自助撤回应留恰好一条 tokens_revoked 审计（subject=本人），实际 %d", revoked)
	}

	if _, err := s.RevokeOwnOAuthGrant(ctx, owner.ID, "mfc-nope-"+strings.ReplaceAll(newUUID(), "-", "")[:8]); err == nil || err.Error() != "client_not_found" {
		t.Fatalf("未知客户端应 client_not_found，实际 %v", err)
	}
	if _, err := s.RevokeOwnOAuthGrant(ctx, "", clientID); err == nil || err.Error() != "authentication_required" {
		t.Fatalf("缺登录身份应 authentication_required，实际 %v", err)
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
