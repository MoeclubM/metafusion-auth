package handler

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 限流的速率/开关真的取自实例设置（而不是构造时的常量）：
// 把上限改成 2 → 第 3 次被 429 拦下；关掉 → 连打不再出现 429。
// 用例会临时改写实例设置，退出前恢复原状（同库的其它包也用这份设置）。
func TestRateLimitUsesInstanceSettingsAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	db := testutil.Database(t)
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st.Tokens = newTestIssuer(t)

	restore := saveSettings(t, db, store.SettingAuthRateLimitEnabled, store.SettingRateLimitPerMinute)
	t.Cleanup(restore)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)
	login := func() int { return doJSON(t, r, http.MethodPost, "/api/auth/login", "", "").Code }

	// 上限 2/分钟：前两次进业务（空体 → 400），第三次被限流。
	if err := st.UpdateSettings(ctx, map[string]any{store.SettingAuthRateLimitEnabled: true, store.SettingRateLimitPerMinute: 2}, settingsActor()); err != nil {
		t.Fatalf("改限流设置: %v", err)
	}
	for i := 0; i < 2; i++ {
		if code := login(); code != http.StatusBadRequest {
			t.Fatalf("上限内第 %d 次应进业务（400），实际 %d", i+1, code)
		}
	}
	if code := login(); code != http.StatusTooManyRequests {
		t.Fatalf("超过设置上限应 429（说明速率取自实例设置），实际 %d", code)
	}

	// 关掉限流：同一引擎、同一 IP 继续打，不该再被拦。
	if err := st.UpdateSettings(ctx, map[string]any{store.SettingAuthRateLimitEnabled: false}, settingsActor()); err != nil {
		t.Fatalf("关闭限流: %v", err)
	}
	for i := 0; i < 20; i++ {
		if code := login(); code == http.StatusTooManyRequests {
			t.Fatalf("关掉限流后第 %d 次仍被拦", i+1)
		}
	}
}

// 自助授权管理的端到端：登录用户 GET 看到自己的授权、DELETE 撤回后令牌失效且列表转为未生效。
func TestOAuthGrantsEndToEndAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testutil.DSN(t))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Init(ctx); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	st.Tokens = newTestIssuer(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)

	memberID, _, memberBearer := insertChainUser(t, ctx, st, "user")
	_, _, adminBearer := insertChainUser(t, ctx, st, "admin")
	clientID := "mfc-grantapi-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	_, secret, err := st.CreateOAuthClient(ctx, store.OAuthClientInput{
		ID:           clientID,
		Name:         strPtrHandler("自助撤回测试应用"),
		RedirectURIs: &[]string{chainCallback},
		Scopes:       &[]string{"openid", "profile"},
	}, &store.User{ID: memberID, Username: "grant-admin", Permissions: []string{"auth.oauth.manage"}})
	if err != nil {
		t.Fatalf("建客户端: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_audit WHERE client_id=$1", clientID)
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_tokens WHERE client_id=$1", clientID)
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_codes WHERE client_id=$1", clientID)
		_, _ = st.DB.ExecContext(context.Background(), "DELETE FROM auth.oauth_clients WHERE id=$1", clientID)
	})
	if err := st.RecordOAuthAudit(ctx, store.OAuthAuditEntry{ActorID: memberID, SubjectID: memberID, ClientID: clientID, Action: store.OAuthActionConsentAllow, Scopes: []string{"openid", "profile"}}); err != nil {
		t.Fatalf("记同意审计: %v", err)
	}
	code, _, err := st.CreateOAuthCode(ctx, clientID, memberID, chainCallback, "openid profile", "", "")
	if err != nil {
		t.Fatalf("发授权码: %v", err)
	}
	grant, err := st.ExchangeOAuthCode(ctx, clientID, secret, code, chainCallback, "")
	if err != nil {
		t.Fatalf("换码: %v", err)
	}

	w := do(t, r, http.MethodGet, "/api/auth/oauth-grants", memberBearer)
	if w.Code != http.StatusOK {
		t.Fatalf("列授权应 200，实际 %d / %s", w.Code, w.Body.String())
	}
	var listed struct {
		Items []store.AuthorizedApp `json:"items"`
	}
	decodeInto(t, w, &listed)
	if len(listed.Items) != 1 || listed.Items[0].ClientID != clientID || !listed.Items[0].Active {
		t.Fatalf("列表应只有该应用且处于生效态: %+v", listed.Items)
	}

	w = do(t, r, http.MethodDelete, "/api/auth/oauth-grants/"+clientID, memberBearer)
	if w.Code != http.StatusOK {
		t.Fatalf("自助撤回应 200，实际 %d / %s", w.Code, w.Body.String())
	}
	var revoked struct {
		OK      bool `json:"ok"`
		Revoked int  `json:"revoked"`
	}
	decodeInto(t, w, &revoked)
	if !revoked.OK || revoked.Revoked < 1 {
		t.Fatalf("应报告撤回条数: %+v", revoked)
	}
	if _, err := st.UserFromOAuthToken(ctx, grant.Token); err == nil {
		t.Fatal("撤回后该第三方令牌必须失效")
	}
	w = do(t, r, http.MethodGet, "/api/auth/oauth-grants", memberBearer)
	decodeInto(t, w, &listed)
	if len(listed.Items) != 1 || listed.Items[0].Active {
		t.Fatalf("撤回后应显示为未生效: %+v", listed.Items)
	}

	// 管理员的按用户吊销端点保持可用（治理路径不受自助端点影响）。
	if w := doJSON(t, r, http.MethodPost, "/api/admin/users/"+memberID+"/revoke-oauth-tokens", adminBearer, ""); w.Code != http.StatusOK {
		t.Fatalf("管理端吊销应仍可用，实际 %d / %s", w.Code, w.Body.String())
	}
}

// settingsActor 是改实例设置用的合成操作者：UpdateSettings 只按权限码判定（不查库）。
func settingsActor() *store.User {
	return &store.User{ID: "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f", Username: "settings-ops", Permissions: []string{"auth.settings.manage"}}
}

// strPtrHandler 造字符串指针，供 OAuthClientInput 的可选字段使用。
func strPtrHandler(s string) *string { return &s }

// saveSettings 记录这些设置键的原值，返回恢复函数（不存在则删除）。
func saveSettings(t *testing.T, db *sql.DB, keys ...string) func() {
	t.Helper()
	type prior struct {
		exists bool
		raw    string
	}
	saved := map[string]prior{}
	for _, k := range keys {
		var raw string
		err := db.QueryRowContext(context.Background(), "SELECT value::text FROM auth.instance_settings WHERE key=$1", k).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			saved[k] = prior{}
			continue
		}
		if err != nil {
			t.Fatalf("读设置 %s: %v", k, err)
		}
		saved[k] = prior{exists: true, raw: raw}
	}
	return func() {
		for _, k := range keys {
			if saved[k].exists {
				_, _ = db.ExecContext(context.Background(), "UPDATE auth.instance_settings SET value=$2::jsonb WHERE key=$1", k, saved[k].raw)
				continue
			}
			_, _ = db.ExecContext(context.Background(), "DELETE FROM auth.instance_settings WHERE key=$1", k)
		}
	}
}
