package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 自助资料端到端（真库）：本人改昵称/简介 200 即时生效；超限 400 带稳定码；
// 未登录 401；未知字段 400（DisallowUnknownFields）；公开读随后即见新值。
// 未设置 AUTH_TEST_DSN 时跳过。
func TestUpdateOwnProfileEndToEnd(t *testing.T) {
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

	put := func(bearer, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/auth/profile", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := put("", `{"display_name":"x"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401，实际 %d（%s）", w.Code, w.Body.String())
	}
	if w := put(memberBearer, `{"display_name":"x","nick":"y"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("未知字段应 400，实际 %d（%s）", w.Code, w.Body.String())
	}
	if w := put(memberBearer, `{"display_name":"`+strings.Repeat("昵", 33)+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("昵称超限应 400，实际 %d（%s）", w.Code, w.Body.String())
	} else {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || payload.Error != "invalid_display_name" {
			t.Fatalf("昵称超限应回 invalid_display_name，实际 %q（err=%v）", payload.Error, err)
		}
	}
	if w := put(memberBearer, `{"bio":"`+strings.Repeat("b", 501)+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("简介超限应 400，实际 %d（%s）", w.Code, w.Body.String())
	}

	w := put(memberBearer, `{"display_name":"阿策","bio":"简介第一行"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("改资料应 200，实际 %d（%s）", w.Code, w.Body.String())
	}
	var updated struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Bio         string `json:"bio"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("解析响应: %v", err)
	}
	if updated.ID != memberID || updated.DisplayName != "阿策" || updated.Bio != "简介第一行" {
		t.Fatalf("响应应带新资料，实际 %+v", updated)
	}

	// 公开读随后即见；/auth/me 同样新鲜（读穿 DB，不等令牌周期）。
	p, err := st.PublicProfile(ctx, memberID, "")
	if err != nil || p.User.DisplayName != "阿策" || p.User.Bio != "简介第一行" {
		t.Fatalf("公开读应即时可见（err=%v）：%+v", err, p.User)
	}
	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+memberBearer)
	meW := httptest.NewRecorder()
	r.ServeHTTP(meW, meReq)
	if meW.Code != http.StatusOK {
		t.Fatalf("/auth/me 应 200，实际 %d（%s）", meW.Code, meW.Body.String())
	}
	var me struct {
		DisplayName string `json:"display_name"`
		Bio         string `json:"bio"`
	}
	if err := json.Unmarshal(meW.Body.Bytes(), &me); err != nil || me.DisplayName != "阿策" || me.Bio != "简介第一行" {
		t.Fatalf("/auth/me 应带新资料，实际 %+v（err=%v）", me, err)
	}
}
