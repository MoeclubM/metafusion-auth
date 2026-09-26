package handler

// 真实 PostgreSQL 上的 PAT 端到端回归：HTTP 创建（201 + 明文只此一次）→ 列表（无明文/无哈希）
// → 内省（身份 + 交集权限 + 不产出 Cookie）→ PAT 不能当登录态 → scopes 越权被拒 → 归属隔离
// → 吊销（幂等）→ 内省 401 → 过期 401。
//
// 未设置 AUTH_TEST_DSN 时整体跳过（本机与 CI 默认没有数据库）。用例自建自清账号。

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// patIntrospect 调内省端点（无凭据，令牌在请求体里，与下游服务的调用形状一致）。
func patIntrospect(t *testing.T, r *gin.Engine, token string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, r, http.MethodPost, "/api/auth/tokens/introspect", "", `{"token":"`+token+`"}`)
}

func TestPersonalAccessTokenHTTPAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err = st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st.Tokens = newTestIssuer(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)

	memberID, memberName, _ := insertChainUser(t, ctx, st, "user")
	// 权限来自权限组（组 → 权限码），因此先入组再登录：访问令牌里的 permissions 是登录那一刻的快照。
	if _, err := st.DB.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id) SELECT $1,id FROM auth.groups WHERE code='catalog_editor'", memberID); err != nil {
		t.Fatalf("加入权限组: %v", err)
	}
	memberBearer, _, err := st.Login(ctx, memberName, chainTestPassword)
	if err != nil {
		t.Fatalf("入组后重新登录: %v", err)
	}
	_, _, otherBearer := insertChainUser(t, ctx, st, "user")

	// ── 创建：201 + 明文只此一次；库里只有哈希 ──
	w := doJSON(t, r, http.MethodPost, "/api/auth/tokens", memberBearer, `{"name":"CI 编目","scopes":["catalog.entity.edit"],"expires_in_days":30}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("创建 PAT: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Token string                    `json:"token"`
		Item  store.PersonalAccessToken `json:"item"`
	}
	decodeInto(t, w, &created)
	plain := created.Token
	if !strings.HasPrefix(plain, "mfp_") || len(plain) != len("mfp_")+43 {
		t.Fatalf("明文形状不符（应为 mfp_ + 43 位 base62）: %q", plain)
	}
	hash := store.HashPersonalAccessToken(plain)
	if strings.Contains(w.Body.String(), hash) {
		t.Fatalf("创建响应绝不能含 token_hash: %s", w.Body.String())
	}
	if created.Item.ID == "" || created.Item.ExpiresAt == nil || !created.Item.Active || created.Item.TokenPrefix != plain[:12] {
		t.Fatalf("创建响应元数据不符: %+v", created.Item)
	}
	var storedHash string
	if err := st.DB.QueryRowContext(ctx, "SELECT token_hash FROM auth.personal_access_tokens WHERE id=$1", created.Item.ID).Scan(&storedHash); err != nil {
		t.Fatalf("读回 PAT 行: %v", err)
	}
	if storedHash != hash || storedHash == plain {
		t.Fatalf("库里应存 sha256 而不是明文: %q", storedHash)
	}
	assertNoSessionCookie(t, w)

	// ── 列表：只含本人、不含明文/哈希 ──
	w = doJSON(t, r, http.MethodGet, "/api/auth/tokens", memberBearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("列表: %d %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, plain) || strings.Contains(body, hash) {
		t.Fatalf("列表不得含明文或 token_hash: %s", body)
	}
	var listed struct {
		Items []store.PersonalAccessToken `json:"items"`
	}
	decodeInto(t, w, &listed)
	if len(listed.Items) != 1 || listed.Items[0].TokenPrefix != created.Item.TokenPrefix || listed.Items[0].LastUsedAt != nil {
		t.Fatalf("列表内容不符: %+v", listed.Items)
	}
	if w := doJSON(t, r, http.MethodGet, "/api/auth/tokens", otherBearer, ""); w.Code != http.StatusOK || strings.Contains(w.Body.String(), created.Item.TokenPrefix) {
		t.Fatalf("列表必须只含本人令牌: %d %s", w.Code, w.Body.String())
	}

	// ── 内省：无凭据可用、不产出 Cookie、权限是交集、last_used_at 写回 ──
	w = patIntrospect(t, r, plain)
	if w.Code != http.StatusOK {
		t.Fatalf("内省: %d %s", w.Code, w.Body.String())
	}
	var principal struct {
		Valid       bool       `json:"valid"`
		TokenID     string     `json:"token_id"`
		TokenName   string     `json:"token_name"`
		UserID      string     `json:"user_id"`
		Username    string     `json:"username"`
		Role        string     `json:"role"`
		Permissions []string   `json:"permissions"`
		Scopes      []string   `json:"scopes"`
		TokenPrefix string     `json:"token_prefix"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}
	decodeInto(t, w, &principal)
	if !principal.Valid || principal.UserID != memberID || principal.Username != memberName {
		t.Fatalf("内省身份不符: %+v", principal)
	}
	if principal.TokenID != created.Item.ID || principal.TokenName != "CI 编目" {
		t.Fatalf("内省应回令牌身份 token_id/token_name: %+v", principal)
	}
	if len(principal.Permissions) != 1 || principal.Permissions[0] != "catalog.entity.edit" || len(principal.Scopes) != 1 {
		t.Fatalf("有效权限应是账号权限 ∩ scopes: %+v", principal)
	}
	if principal.ExpiresAt == nil || principal.TokenPrefix != created.Item.TokenPrefix {
		t.Fatalf("内省元数据不符: %+v", principal)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("内省必须 no-store: %q", w.Header().Get("Cache-Control"))
	}
	assertNoSessionCookie(t, w)
	var lastUsed sql.NullTime
	if err := st.DB.QueryRowContext(ctx, "SELECT last_used_at FROM auth.personal_access_tokens WHERE id=$1", created.Item.ID).Scan(&lastUsed); err != nil || !lastUsed.Valid {
		t.Fatalf("内省后应写 last_used_at: %v err=%v", lastUsed, err)
	}

	// ── PAT 不是登录态：拿明文当 Bearer 不能列令牌、也不能再创建令牌 ──
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/auth/tokens", ""},
		{http.MethodPost, "/api/auth/tokens", `{"name":"PAT 不该能建 PAT","scopes":["catalog.entity.edit"]}`},
	} {
		w := doJSON(t, r, tc.method, tc.path, plain, tc.body)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("PAT 不能当登录态用（%s %s）: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// ── scopes 超出本人权限：400 + 稳定机器码（不静默取交集） ──
	w = doJSON(t, r, http.MethodPost, "/api/auth/tokens", memberBearer, `{"name":"提权","scopes":["auth.users.manage"]}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "scope_not_granted: auth.users.manage") {
		t.Fatalf("越权 scope 应 400 scope_not_granted: %d %s", w.Code, w.Body.String())
	}

	// ── 归属隔离：吊销别人的令牌按"不存在"处理 ──
	if w := doJSON(t, r, http.MethodDelete, "/api/auth/tokens/"+created.Item.ID, otherBearer, ""); w.Code != http.StatusNotFound {
		t.Fatalf("不能吊销别人的令牌: %d %s", w.Code, w.Body.String())
	}

	// ── 吊销：幂等，之后内省 401 ──
	for i := 0; i < 2; i++ {
		w := doJSON(t, r, http.MethodDelete, "/api/auth/tokens/"+created.Item.ID, memberBearer, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "true") {
			t.Fatalf("第 %d 次吊销应 200 ok: %d %s", i+1, w.Code, w.Body.String())
		}
	}
	w = patIntrospect(t, r, plain)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_token") {
		t.Fatalf("吊销后内省应 401 invalid_token: %d %s", w.Code, w.Body.String())
	}
	w = doJSON(t, r, http.MethodGet, "/api/auth/tokens", memberBearer, "")
	decodeInto(t, w, &listed)
	if len(listed.Items) != 1 || listed.Items[0].RevokedAt == nil || listed.Items[0].Active {
		t.Fatalf("吊销是写 revoked_at 而不是删行: %+v", listed.Items)
	}

	// ── 过期：把 expires_at 拨到过去（HTTP 最短有效期是 1 天，用 SQL 造过期态） ──
	w = doJSON(t, r, http.MethodPost, "/api/auth/tokens", memberBearer, `{"name":"短命","scopes":["catalog.entity.edit"],"expires_in_days":1}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("创建带有效期的令牌: %d %s", w.Code, w.Body.String())
	}
	var shortLived struct {
		Token string                    `json:"token"`
		Item  store.PersonalAccessToken `json:"item"`
	}
	decodeInto(t, w, &shortLived)
	if _, err := st.DB.ExecContext(ctx, "UPDATE auth.personal_access_tokens SET expires_at=now()-interval '1 hour' WHERE id=$1", shortLived.Item.ID); err != nil {
		t.Fatalf("造过期态: %v", err)
	}
	w = patIntrospect(t, r, shortLived.Token)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_token") {
		t.Fatalf("过期令牌应 401 invalid_token: %d %s", w.Code, w.Body.String())
	}
	// 过期与吊销是两件事：列表里 active=false 但 revoked_at 仍为空。
	w = doJSON(t, r, http.MethodGet, "/api/auth/tokens", memberBearer, "")
	decodeInto(t, w, &listed)
	foundExpired := false
	for _, it := range listed.Items {
		if it.ID == shortLived.Item.ID {
			foundExpired = true
			if it.Active || it.RevokedAt != nil || it.ExpiresAt == nil {
				t.Fatalf("过期令牌的投影不符: %+v", it)
			}
		}
	}
	if !foundExpired {
		t.Fatalf("过期令牌仍应出现在列表里: %+v", listed.Items)
	}
}
