package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 非法 id 必须在碰库之前被拒：把非 uuid 丢给 postgres 会得到 22P02，那会以 500（或 400）
// 告诉外面"这个参数进了 SQL"；同一个"没有这个账号"也不该因写法不同而拿到不同状态码。
// 这条用例不需要数据库（桩实例的 s.DB 为 nil）。
func TestPublicUserProfileRejectsNonUUID(t *testing.T) {
	r, _ := newTestServer(t)
	for _, id := range []string{"not-a-uuid", "123", "11111111-1111-1111-1111-11111111111", "11111111-1111-1111-1111-11111111111z"} {
		w := do(t, r, http.MethodGet, "/api/users/"+id, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("/api/users/%s 应 404，实际 %d（%s）", id, w.Code, w.Body.String())
			continue
		}
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || payload.Error != "not_found" {
			t.Errorf("/api/users/%s 应回 not_found，实际 %q（err=%v）", id, payload.Error, err)
		}
	}
}

// 端到端（真库）：匿名与"登录着看别人"都拿不到 email，只有本人能拿到；
// 响应里不得出现 password_hash / 组与权限；不存在的 uuid 是 404 not_found。
// 未设置 AUTH_TEST_DSN 时跳过。
func TestPublicUserProfilePrivacyAcrossIdentities(t *testing.T) {
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

	memberID, memberName, memberBearer := insertChainUser(t, ctx, st, "user")
	_, _, otherBearer := insertChainUser(t, ctx, st, "user")

	type envelope struct {
		User  map[string]any `json:"user"`
		Stats map[string]any `json:"stats"`
	}
	read := func(t *testing.T, bearer string) envelope {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/users/"+memberID, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("读公开资料应 200，实际 %d / %s", w.Code, w.Body.String())
		}
		var env envelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatalf("解析响应: %v", err)
		}
		for _, secret := range []string{"password_hash", "groups", "permissions"} {
			if _, ok := env.User[secret]; ok {
				t.Fatalf("公开资料不得带 %s：%v", secret, env.User)
			}
		}
		return env
	}

	anon := read(t, "")
	if anon.User["id"] != memberID || anon.User["username"] != memberName {
		t.Fatalf("匿名应能读到 id/username，实际 %v", anon.User)
	}
	if _, ok := anon.User["email"]; ok {
		t.Fatalf("匿名读别人不得带 email：%v", anon.User)
	}
	if _, ok := anon.Stats["invited_count"]; !ok {
		t.Fatalf("stats.invited_count 应在响应里（此刻为 0）：%v", anon.Stats)
	}

	if other := read(t, otherBearer); other.User["id"] != memberID {
		t.Fatalf("登录用户读别人应拿到目标账号，实际 %v", other.User)
	} else if _, ok := other.User["email"]; ok {
		t.Fatalf("登录用户读别人的资料不得带 email：%v", other.User)
	}

	self := read(t, memberBearer)
	email, _ := self.User["email"].(string)
	if email != memberName+"@example.test" {
		t.Fatalf("本人应能读到自己的 email，实际 %q", email)
	}

	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		w := do(t, r, http.MethodGet, "/api/users/"+id, "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("/api/users/%s 应 404，实际 %d（%s）", id, w.Code, w.Body.String())
		}
	}
}
