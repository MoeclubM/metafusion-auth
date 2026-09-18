package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
	"github.com/MoeclubM/metafusion-auth/internal/testutil"
)

// 写接口的未知字段一律拒绝（与目录、互动、存储三个服务同口径）：
// POST /api/setup 此前用 ShouldBindJSON，把 site_name / registration_enabled / invite_required
// 静默吞掉——初始化向导的载荷里带着它们，调用方以为这些开关已经生效。
// 这里断言请求在进入业务之前就被 400 invalid_payload 拦下（不碰数据库）。
func TestWriteEndpointsRejectUnknownFields(t *testing.T) {
	r, s := newTestServer(t)
	const pw = "a-long-enough-password"
	// 管理面端点先过权限闸门再看载荷：这里带一个只持 auth.invites.manage 的令牌，
	// 证明"未知字段被拒"发生在业务之前，而不是被 401/403 掩盖。
	inviteOps := signBearer(t, s, store.User{
		ID: "88888888-8888-8888-8888-888888888888", Username: "invite-ops", Role: "user",
		Permissions: []string{"auth.invites.manage"},
	})
	cases := []struct{ name, method, path, bearer, payload string }{
		{"setup 带 site_name", http.MethodPost, "/api/setup", "", `{"username":"admin","email":"a@b.c","password":"` + pw + `","site_name":"MyInstance"}`},
		{"setup 带 registration_enabled", http.MethodPost, "/api/setup", "", `{"username":"admin","email":"a@b.c","password":"` + pw + `","registration_enabled":true}`},
		{"login 字段名拼错", http.MethodPost, "/api/auth/login", "", `{"usernmae":"admin","password":"` + pw + `"}`},
		{"register 带 display_name", http.MethodPost, "/api/auth/register", "", `{"username":"newbie","email":"n@b.c","password":"` + pw + `","display_name":"Newbie"}`},
		{"invite 带未知键", http.MethodPost, "/api/admin/invites", inviteOps, `{"note":"x","max_uses":1,"expires_in_days":7,"who":"me"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, r, tc.method, tc.path, tc.bearer, tc.payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("未知字段应在业务前 400，实际 %d：%s", w.Code, w.Body.String())
			}
			var out struct {
				Error string `json:"error"`
			}
			decodeInto(t, w, &out)
			if out.Error != "invalid_payload" {
				t.Fatalf("错误码应为 invalid_payload，实际 %q", out.Error)
			}
		})
	}
}

// 收紧未知字段不能顺手把正常路径拦掉：三字段的载荷必须进得去业务。
// 真库已有账号时按 setup_complete 回绝，空库时会真的建号——两种结果都证明 body() 认这份字段集
// （把 400 invalid_payload 判成失败即可区分）。未设 AUTH_TEST_DSN 时跳过。
func TestSetupBodyAcceptsDeclaredFieldsAgainstPostgres(t *testing.T) {
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

	gin.SetMode(gin.TestMode)
	r := gin.New()
	New(st).Register(r)

	w := doJSON(t, r, http.MethodPost, "/api/setup", "",
		`{"username":"oobe-probe","email":"oobe@example.com","password":"a-long-enough-password"}`)
	var out struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	decodeInto(t, w, &out)
	if out.Error == "invalid_payload" {
		t.Fatalf("声明过的字段集不该被判成未知字段：%s", w.Body.String())
	}
	if w.Code == http.StatusOK {
		if out.ID == "" {
			t.Fatalf("建号成功应回账号投影：%s", w.Body.String())
		}
		// 写入后读回：初始化状态必须变成"已完成"。
		status := do(t, r, http.MethodGet, "/api/setup", "")
		var st2 struct {
			IsInitialized bool `json:"is_initialized"`
		}
		decodeInto(t, status, &st2)
		if !st2.IsInitialized {
			t.Fatalf("建号后 GET /api/setup 应报 is_initialized=true：%s", status.Body.String())
		}
		testutil.DeleteUser(t, db, out.ID)
		return
	}
	if out.Error != "setup_complete" {
		t.Fatalf("允许的失败只有 setup_complete，实际 %d %s", w.Code, w.Body.String())
	}
}
