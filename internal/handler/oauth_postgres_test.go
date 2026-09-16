package handler

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 真实 PostgreSQL 上的完整链路回归：httptest 驱动 authorize → 同意页 → 授权码 → 令牌 →
// userinfo，再走一遍客户端管理 API（创建 / 轮换密钥 / 吊销 / 停用 / 删除）。
//
// 未设置 AUTH_TEST_DSN 时整体跳过（本机与 CI 默认没有数据库）。跑法：
//
//	AUTH_TEST_DSN='postgres://user:pw@127.0.0.1:5432/metafusion_test?sslmode=disable' //	  go test ./internal/handler -run TestOAuthChainAgainstPostgres -v
//
// 连接串必须指向独立测试库（库名含 _test，testutil 会强制校验）；用例自建自清账号、
// 客户端与审计行，不读取也不修改既有数据。
func TestOAuthChainAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st.Tokens = newTestIssuer(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)

	memberID, memberName, memberBearer := insertChainUser(t, ctx, st, "user")
	_, _, adminBearer := insertChainUser(t, ctx, st, "admin")
	const callback = "https://client.example/auth/callback"
	clientID := "mfc-chain-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	_ = memberName
	t.Cleanup(func() {
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_audit WHERE client_id=$1", clientID)
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_clients WHERE id=$1", clientID)
	})

	// ── 管理 API：创建客户端（明文密钥只返回一次）──
	createBody := `{"client_id":"` + clientID + `","name":"链路测试站点","redirect_uris":["` + callback + `"],"scopes":["openid","profile"],"trusted":false}`
	w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", adminBearer, createBody)
	if w.Code != http.StatusOK {
		t.Fatalf("创建客户端: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Client       store.OAuthClient `json:"client"`
		ClientSecret string            `json:"client_secret"`
	}
	decodeInto(t, w, &created)
	if created.Client.SecretHash != "" {
		t.Fatal("对外响应不得携带密钥哈希")
	}
	if len(created.ClientSecret) != 43 {
		t.Fatalf("明文密钥长度不符: %d", len(created.ClientSecret))
	}
	var storedHash string
	if err := st.DB.QueryRowContext(ctx, "SELECT secret_hash FROM auth.oauth_clients WHERE id=$1", clientID).Scan(&storedHash); err != nil {
		t.Fatalf("读 secret_hash: %v", err)
	}
	if storedHash == created.ClientSecret || !strings.HasPrefix(storedHash, "$2") {
		t.Fatalf("库里必须只有 bcrypt 哈希: %q", storedHash)
	}
	// 权限边界：匿名 401、普通成员 403
	if w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", "", createBody); w.Code != http.StatusUnauthorized {
		t.Fatalf("匿名创建应 401，实际 %d", w.Code)
	}
	if w := doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients", memberBearer, createBody); w.Code != http.StatusForbidden {
		t.Fatalf("无码成员创建应 403，实际 %d", w.Code)
	}

	// ── 授权：先出同意页，再允许 → 拿码 ──
	authQuery := "client_id=" + clientID + "&redirect_uri=" + url.QueryEscape(callback) +
		"&response_type=code&state=st-1&scope=" + url.QueryEscape("openid profile email")
	w = authorize(t, r, memberBearer, authQuery)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "链路测试站点") || !strings.Contains(w.Body.String(), "consent=allow") {
		t.Fatalf("同意页不符: %d %s", w.Code, w.Body.String())
	}
	code := codeFromRedirect(t, authorize(t, r, memberBearer, authQuery+"&consent=allow"), callback)

	// ── 换令牌：scope 收敛（客户端白名单只有 openid/profile）、expires_in 真实 ──
	w = postToken(t, r, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"client_secret": {created.ClientSecret}, "redirect_uri": {callback},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("换令牌: %d %s", w.Code, w.Body.String())
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		IDToken     string `json:"id_token"`
	}
	decodeInto(t, w, &tokenResp)
	if tokenResp.Scope != "openid profile" {
		t.Fatalf("scope = %q，期望收敛后的 openid profile", tokenResp.Scope)
	}
	if tokenResp.ExpiresIn != int(store.AccessTokenTTL.Seconds()) {
		t.Fatalf("expires_in = %d，期望 %d", tokenResp.ExpiresIn, int(store.AccessTokenTTL.Seconds()))
	}
	if tokenResp.IDToken == "" {
		t.Fatal("OIDC 客户端应同时拿到 id_token")
	}

	// ── userinfo：真实库里的存活行 ──
	w = userinfo(t, r, tokenResp.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
	}
	var info struct {
		Sub string `json:"sub"`
	}
	decodeInto(t, w, &info)
	if info.Sub != memberID {
		t.Fatalf("userinfo sub = %s，期望 %s", info.Sub, memberID)
	}

	// ── 密钥轮换：老密钥立刻失效 ──
	w = doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients/"+clientID+"/rotate-secret", adminBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("轮换密钥: %d %s", w.Code, w.Body.String())
	}
	var rotated struct {
		ClientSecret string `json:"client_secret"`
	}
	decodeInto(t, w, &rotated)
	if rotated.ClientSecret == created.ClientSecret || rotated.ClientSecret == "" {
		t.Fatalf("轮换应换出新的明文密钥")
	}
	code = codeFromRedirect(t, authorize(t, r, memberBearer, authQuery+"&consent=allow"), callback)
	w = postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "client_secret": {created.ClientSecret}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_client_secret") {
		t.Fatalf("老密钥必须失效: %d %s", w.Code, w.Body.String())
	}
	w = postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "client_secret": {rotated.ClientSecret}})
	if w.Code != http.StatusOK {
		t.Fatalf("新密钥应可用: %d %s", w.Code, w.Body.String())
	}
	decodeInto(t, w, &tokenResp)

	// ── 吊销：userinfo 立即 401 ──
	w = doJSON(t, r, http.MethodPost, "/api/admin/oauth/clients/"+clientID+"/revoke-tokens", adminBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("按客户端吊销: %d %s", w.Code, w.Body.String())
	}
	var revoked struct {
		Revoked int `json:"revoked"`
	}
	decodeInto(t, w, &revoked)
	if revoked.Revoked < 1 {
		t.Fatalf("应至少吊销 1 枚存活令牌，实际 %d", revoked.Revoked)
	}
	if w := userinfo(t, r, tokenResp.AccessToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("吊销后 userinfo 应 401，实际 %d", w.Code)
	}

	// ── 审计：同意动作可查 ──
	w = doJSON(t, r, http.MethodGet, "/api/admin/oauth/audits?client_id="+clientID, adminBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("读审计: %d %s", w.Code, w.Body.String())
	}
	var audits struct {
		Items []store.OAuthAuditEntry `json:"items"`
	}
	decodeInto(t, w, &audits)
	seen := map[string]bool{}
	for _, item := range audits.Items {
		seen[item.Action] = true
	}
	for _, action := range []string{store.OAuthActionConsentAllow, store.OAuthActionClientCreate, store.OAuthActionClientRotate, store.OAuthActionTokensRevoked} {
		if !seen[action] {
			t.Fatalf("审计缺少 %s: %v", action, seen)
		}
	}

	// ── 停用 → 删除 ──
	if w := doJSON(t, r, http.MethodPut, "/api/admin/oauth/clients/"+clientID, adminBearer, `{"disabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("停用: %d %s", w.Code, w.Body.String())
	}
	if w := authorize(t, r, memberBearer, authQuery); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_client") {
		t.Fatalf("停用后不能再发起授权: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, r, http.MethodDelete, "/api/admin/oauth/clients/"+clientID, adminBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("删除: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, r, http.MethodGet, "/api/oauth/clients", memberBearer, ""); w.Code != http.StatusOK || strings.Contains(w.Body.String(), clientID) {
		t.Fatalf("删除后列表里不应再出现该客户端: %d %s", w.Code, w.Body.String())
	}
}

const chainTestPassword = "oauth-chain-secret"

// insertChainUser 建一个真实账号并登录，返回 (id, 用户名, 登录令牌)：身份与令牌走的是
// 生产同一条路径（bcrypt 口令 + RS256 签发 + 会话行）。
func insertChainUser(t *testing.T, ctx context.Context, st *store.Store, role string) (string, string, string) {
	t.Helper()
	id := uuid.NewString()
	name := "oauth-" + role + "-" + strings.ReplaceAll(id, "-", "")[:10]
	hash, err := bcrypt.GenerateFromPassword([]byte(chainTestPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("哈希测试口令: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash,role) VALUES($1,$2,$3,$4,$5)", id, name, name+"@example.test", string(hash), role); err != nil {
		t.Fatalf("插入测试账号: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.users WHERE id=$1", id)
	})
	token, _, err := st.Login(ctx, name, chainTestPassword)
	if err != nil {
		t.Fatalf("登录测试账号: %v", err)
	}
	return id, name, token
}
