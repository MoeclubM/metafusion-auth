package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// OAuth 授权方的真实库回归：创建客户端 → 发码（scope 收敛 + PKCE）→ 换码 → userinfo →
// 轮换密钥 → 按客户端/按用户吊销 → 停用 → 删除，外加审计留痕。
//
// 未设置 AUTH_TEST_DSN 时整体跳过（本机与 CI 默认不依赖数据库）。跑法：
//
//	AUTH_TEST_DSN='postgres://user:pw@127.0.0.1:5432/metafusion_test?sslmode=disable' //	  go test ./internal/store -run TestOAuthServerAgainstPostgres -v
//
// 连接串必须指向独立测试库（库名含 _test，testutil 会强制校验）。
func TestOAuthServerAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// 收尾要删账号与客户端，注册成 t.Cleanup 才能排在它们之后（defer 会先把连接关掉，删除静默失败）。
	t.Cleanup(func() { s.Close() })
	// Init 幂等：这里同时验证 scopes / disabled / jti 三个增量列与审计表能在既有库上补上。
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	s.Tokens = newTestIssuer(t)

	const callback = "https://client.example/auth/callback"
	userID := seedOAuthTestUser(t, ctx, s)
	admin := &User{ID: userID, Username: "oauth-admin", Permissions: []string{"auth.oauth.manage"}}
	member := &User{ID: userID, Username: "oauth-member"}
	clientID := "mfc-test-" + strings.ReplaceAll(newUUID(), "-", "")[:12]
	// 轮换后的当前密钥：轮换接口只返回一次明文，这里存下来给后面的换码用。
	currentSecret := ""

	// ── 管理 API：创建客户端（明文密钥只返回这一次）──
	client, secret, err := s.CreateOAuthClient(ctx, OAuthClientInput{
		ID:           clientID,
		Name:         strPtr("测试第三方站点"),
		RedirectURIs: &[]string{callback},
		Scopes:       &[]string{"openid", "profile"},
	}, admin)
	if err != nil {
		t.Fatalf("创建客户端: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_audit WHERE client_id=$1", clientID)
		_, _ = s.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_clients WHERE id=$1", clientID)
	})
	if secret == "" || client.ID != clientID || client.Trusted || client.Disabled || len(client.Scopes) != 2 {
		t.Fatalf("创建结果不符: %+v secret=%q", client, secret)
	}
	var storedHash string
	if err := s.DB.QueryRowContext(ctx, "SELECT secret_hash FROM auth.oauth_clients WHERE id=$1", clientID).Scan(&storedHash); err != nil {
		t.Fatalf("读 secret_hash: %v", err)
	}
	if storedHash == secret || !strings.HasPrefix(storedHash, "$2") {
		t.Fatalf("库里必须只留 bcrypt 哈希: %q", storedHash)
	}
	if _, _, err := s.CreateOAuthClient(ctx, OAuthClientInput{ID: clientID, Name: strPtr("重复"), RedirectURIs: &[]string{callback}}, admin); err == nil {
		t.Fatal("重复 client_id 必须拒绝")
	}
	if _, _, err := s.CreateOAuthClient(ctx, OAuthClientInput{Name: strPtr("通配回调"), RedirectURIs: &[]string{"https://*.client.example/cb"}}, admin); err == nil {
		t.Fatal("通配回调必须拒绝")
	}
	if _, _, err := s.CreateOAuthClient(ctx, OAuthClientInput{Name: strPtr("越权 scope"), RedirectURIs: &[]string{callback}, Scopes: &[]string{"openid", "phone"}}, admin); err == nil {
		t.Fatal("白名单外的 scope 必须拒绝")
	}
	if _, _, err := s.CreateOAuthClient(ctx, OAuthClientInput{Name: strPtr("无权限"), RedirectURIs: &[]string{callback}}, member); err == nil {
		t.Fatal("无 auth.oauth.manage 的成员必须 forbidden")
	}

	// ── scope 收敛：请求三个、白名单两个，写进码里的只能是交集 ──
	code, scope, err := s.CreateOAuthCode(ctx, clientID, userID, callback, "openid profile email", "", "")
	if err != nil {
		t.Fatalf("发码: %v", err)
	}
	if scope != "openid profile" {
		t.Fatalf("收敛后的 scope = %q，期望 openid profile", scope)
	}
	var storedScope string
	if err := s.DB.QueryRowContext(ctx, "SELECT scope FROM auth.oauth_codes WHERE code=$1", code).Scan(&storedScope); err != nil || storedScope != "openid profile" {
		t.Fatalf("授权码里落的 scope = %q err=%v", storedScope, err)
	}
	if _, _, err := s.CreateOAuthCode(ctx, clientID, userID, callback, "phone", "", ""); err == nil {
		t.Fatal("不受支持的 scope 必须拒绝")
	}
	if _, _, err := s.CreateOAuthCode(ctx, clientID, userID, "https://evil.example/cb", "openid", "", ""); err == nil {
		t.Fatal("非白名单回调必须拒绝")
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, secret, code, callback, ""); err != nil {
		t.Fatalf("无 PKCE 的码应能兑换: %v", err)
	}

	// ── PKCE：错误的 verifier 不能消耗授权码 ──
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFG"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code, _, err = s.CreateOAuthCode(ctx, clientID, userID, callback, "openid profile", challenge, "S256")
	if err != nil {
		t.Fatalf("发码(PKCE): %v", err)
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, secret, code, callback, "wrong-verifier"); err == nil || err.Error() != "invalid_code_verifier" {
		t.Fatalf("错误 verifier 应报 invalid_code_verifier，实际 %v", err)
	}
	grant, err := s.ExchangeOAuthCode(ctx, clientID, secret, code, callback, verifier)
	if err != nil {
		t.Fatalf("PKCE 校验失败后同一枚码应仍可兑换: %v", err)
	}
	if grant.Token == "" || grant.Scope != "openid profile" || grant.ExpiresIn <= 0 || grant.User == nil || grant.User.ID != userID {
		t.Fatalf("换码结果不符: %+v", grant)
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, secret, code, callback, verifier); err == nil {
		t.Fatal("授权码必须一次性")
	}
	code, _, err = s.CreateOAuthCode(ctx, clientID, userID, callback, "openid", "", "")
	if err != nil {
		t.Fatalf("发码(回调校验): %v", err)
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, secret, code, "https://client.example/other", ""); err == nil || err.Error() != "redirect_uri_mismatch" {
		t.Fatalf("回调不一致应报 redirect_uri_mismatch，实际 %v", err)
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, "wrong-secret", code, callback, ""); err == nil || err.Error() != "invalid_client_secret" {
		t.Fatalf("错误密钥应报 invalid_client_secret，实际 %v", err)
	}

	// ── userinfo：以存活行为准（含 scope）──
	who, whoScope, err := s.OAuthUserinfo(ctx, grant.Token)
	if err != nil || who == nil || who.ID != userID || whoScope != "openid profile" {
		t.Fatalf("userinfo = %+v scope=%q err=%v", who, whoScope, err)
	}
	var jti string
	if err := s.DB.QueryRowContext(ctx, "SELECT jti FROM auth.oauth_tokens WHERE token_hash=$1", sessionHash(grant.Token)).Scan(&jti); err != nil || jti == "" {
		t.Fatalf("令牌行应记录 jti（批量吊销要用）: jti=%q err=%v", jti, err)
	}

	// ── 密钥轮换：老密钥立即失效 ──
	if _, _, err := s.RotateOAuthClientSecret(ctx, clientID, member); err == nil {
		t.Fatal("无权限不能轮换密钥")
	}
	rotated, newSecret, err := s.RotateOAuthClientSecret(ctx, clientID, admin)
	if err != nil {
		t.Fatalf("轮换密钥: %v", err)
	}
	if !strings.HasPrefix(rotated.SecretHash, "$2") || rotated.SecretHash == storedHash {
		t.Fatalf("轮换后 secret_hash 应换成新的哈希: %q", rotated.SecretHash)
	}
	currentSecret = newSecret
	code2, _, err := s.CreateOAuthCode(ctx, clientID, userID, callback, "openid", "", "")
	if err != nil {
		t.Fatalf("轮换后发码: %v", err)
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, secret, code2, callback, ""); err == nil {
		t.Fatal("轮换后老密钥必须失效")
	}
	if _, err := s.ExchangeOAuthCode(ctx, clientID, newSecret, code2, callback, ""); err != nil {
		t.Fatalf("轮换后的新密钥应可用: %v", err)
	}

	// ── 按客户端吊销：存活令牌与未兑换的码一起作废 ──
	if _, err := s.RevokeOAuthTokensByClient(ctx, clientID, member); err == nil {
		t.Fatal("无权限不能吊销令牌")
	}
	n, err := s.RevokeOAuthTokensByClient(ctx, clientID, admin)
	if err != nil || n < 2 {
		t.Fatalf("按客户端吊销 = %d err=%v（期望至少 2 枚存活令牌）", n, err)
	}
	if _, _, err := s.OAuthUserinfo(ctx, grant.Token); err == nil {
		t.Fatal("吊销后 userinfo 必须拒绝")
	}

	// ── 按用户吊销 ──
	code3, _, err := s.CreateOAuthCode(ctx, clientID, userID, callback, "openid", "", "")
	if err != nil {
		t.Fatalf("发码(按用户吊销前): %v", err)
	}
	grant3, err := s.ExchangeOAuthCode(ctx, clientID, currentSecret, code3, callback, "")
	if err != nil {
		t.Fatalf("换码(按用户吊销前): %v", err)
	}
	if _, _, err := s.OAuthUserinfo(ctx, grant3.Token); err != nil {
		t.Fatalf("吊销前 userinfo 应可用: %v", err)
	}
	if n, err := s.RevokeOAuthTokensByUser(ctx, userID, admin); err != nil || n < 1 {
		t.Fatalf("按用户吊销 = %d err=%v", n, err)
	}
	if _, _, err := s.OAuthUserinfo(ctx, grant3.Token); err == nil {
		t.Fatal("按用户吊销后 userinfo 必须拒绝")
	}

	// ── 停用：不能再发码，已发出的令牌也取不到 userinfo ──
	code4, _, err := s.CreateOAuthCode(ctx, clientID, userID, callback, "openid", "", "")
	if err != nil {
		t.Fatalf("发码(停用前): %v", err)
	}
	grant4, err := s.ExchangeOAuthCode(ctx, clientID, currentSecret, code4, callback, "")
	if err != nil {
		t.Fatalf("换码(停用前): %v", err)
	}
	disabled := true
	if _, err := s.UpdateOAuthClient(ctx, clientID, OAuthClientInput{Disabled: &disabled}, admin); err != nil {
		t.Fatalf("停用客户端: %v", err)
	}
	if _, _, err := s.CreateOAuthCode(ctx, clientID, userID, callback, "openid", "", ""); err == nil {
		t.Fatal("停用后不允许再发码")
	}
	if _, _, err := s.OAuthUserinfo(ctx, grant4.Token); err == nil {
		t.Fatal("停用后 userinfo 必须拒绝")
	}

	// ── 审计：创建 / 轮换 / 更新 / 吊销 / 同意都留痕 ──
	if err := s.RecordOAuthAudit(ctx, OAuthAuditEntry{ActorID: userID, SubjectID: userID, ClientID: clientID, Action: OAuthActionConsentAllow, Scopes: []string{"openid", "profile"}, Detail: callback}); err != nil {
		t.Fatalf("写同意审计: %v", err)
	}
	audits, err := s.ListOAuthAudits(ctx, clientID, 50)
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range audits {
		if e.Scopes == nil {
			t.Fatal("审计的 scopes 应为数组而不是 null")
		}
		seen[e.Action] = true
	}
	for _, action := range []string{OAuthActionClientCreate, OAuthActionClientRotate, OAuthActionClientUpdate, OAuthActionTokensRevoked, OAuthActionConsentAllow} {
		if !seen[action] {
			t.Fatalf("审计缺少动作 %s：%v", action, seen)
		}
	}

	// ── 删除：种子客户端不可删；普通客户端删除后码/令牌级联清除，审计保留 ──
	if err := s.DeleteOAuthClient(ctx, "metafusion-forum", admin); err == nil {
		t.Fatal("第一方种子客户端不允许删除")
	}
	if err := s.DeleteOAuthClient(ctx, clientID, member); err == nil {
		t.Fatal("无权限不能删除客户端")
	}
	if err := s.DeleteOAuthClient(ctx, clientID, admin); err != nil {
		t.Fatalf("删除客户端: %v", err)
	}
	if _, err := s.GetOAuthClient(ctx, clientID); err == nil {
		t.Fatal("删除后应查不到客户端")
	}
	var left int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.oauth_tokens WHERE client_id=$1", clientID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("删除客户端后令牌行应级联清除，剩余 %d err=%v", left, err)
	}
	after, err := s.ListOAuthAudits(ctx, clientID, 5)
	if err != nil || len(after) == 0 {
		t.Fatalf("客户端删除后审计必须保留: %v %d", err, len(after))
	}
	if after[0].Action != OAuthActionClientDelete {
		t.Fatalf("最新审计应为 client_deleted，实际 %s", after[0].Action)
	}
}

// strPtr 取字符串字面量的地址：OAuthClientInput 用指针区分「没传」与「传了零值」。
func strPtr(s string) *string { return &s }

// seedOAuthTestUser 直接插一条账号行：本用例只验证 OAuth 侧，不需要走注册/登录流程。
// 需要真实库时用例已确保库名含 _test（见 testutil.DSN）。
func seedOAuthTestUser(t *testing.T, ctx context.Context, s *Store) string {
	t.Helper()
	id := newUUID()
	name := "oauth-test-" + strings.ReplaceAll(id, "-", "")[:10]
	hash, err := bcrypt.GenerateFromPassword([]byte("oauth-test-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("哈希测试口令: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash) VALUES($1,$2,$3,$4)", id, name, name+"@example.test", string(hash)); err != nil {
		t.Fatalf("插入测试账号: %v", err)
	}
	t.Cleanup(func() { testutil.DeleteUser(t, s.DB, id) })
	return id
}
