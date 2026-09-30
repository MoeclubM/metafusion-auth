package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/audit"
	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// auditActionCodeRe 是动作码的形状：<域>.<过去式动作>，全小写 + 下划线。
// 它是机器码，前端与排障脚本按它过滤，任意字符串会让聚合查询断掉。
var auditActionCodeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// 写路由覆盖守卫：这是"所有修改操作都有留痕"这句话的唯一强制性保证——
// 新增写端点却忘了登记动作码，测试直接失败，而不是安静地少留一条痕。
//
// 三条断言：① 每条写路由要么登记、要么在豁免表里（且理由非空）；
// ② 注册表里的动作码形状合法；③ 注册表里没有已不存在的路由（改路由名时同步改这里）。
func TestEveryWriteRouteIsAuditedOrExempted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// 不建库：这里只枚举路由表，不发起请求。
	New(&store.Store{}).Register(r)

	actions := auditActions()
	exempt := auditExempt()
	seen := map[string]bool{}
	for _, route := range r.Routes() {
		switch route.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			continue
		}
		key := route.Method + " " + route.Path
		if _, ok := actions[key]; ok {
			seen[key] = true
			continue
		}
		if reason, ok := exempt[key]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Fatalf("写路由 %s 的豁免必须写明理由（豁免表在 audit_actions.go）", key)
			}
			seen[key] = true
			continue
		}
		t.Fatalf("写路由 %s 既没登记动作码也没进豁免表：请补 auditActions() 或 auditExempt()（契约见 docs/architecture/audit-log.md）", key)
	}
	if len(seen) == 0 {
		t.Fatal("没有枚举到任何写路由：路由表或中间件接线可能有问题")
	}
	for key, action := range actions {
		if !auditActionCodeRe.MatchString(action) {
			t.Fatalf("动作码 %q（%s）不符合 <域>.<动作> 形状", action, key)
		}
		if !seen[key] {
			t.Fatalf("注册表里的 %s 在路由表里不存在：路由改名后忘了同步 auditActions()", key)
		}
	}
}

// 豁免必须有理由，且理由不能是占位符：豁免是"知道这里有写操作但决定不留痕"的显式声明。
func TestAuditExemptionsCarryReasons(t *testing.T) {
	for route, reason := range auditExempt() {
		if len([]rune(strings.TrimSpace(reason))) < 8 {
			t.Fatalf("豁免 %s 的理由太短，写清为什么：%q", route, reason)
		}
		if _, taken := auditActions()[route]; taken {
			t.Fatalf("%s 同时出现在注册表与豁免表里", route)
		}
	}
}

// 读取面的查询参数校验（不建库）：非法值一律 400 invalid_query:<参数>，不静默回落。
func TestParseAuditQueryRejectsInvalidFilters(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"actor_user_id 非 uuid", "actor_user_id=abc"},
		{"result 取值非法", "result=maybe"},
		{"page 为 0", "page=0"},
		{"page 非数字", "page=x"},
		{"per_page 超上限", "per_page=500"},
		{"from 非 RFC3339", "from=2026-09-19"},
		{"to 早于 from", "from=2026-09-19T10:00:00Z&to=2026-09-19T09:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(nil)
			c.Request = httptest.NewRequest("GET", "/api/admin/audit-logs?"+tc.query, nil)
			if _, err := parseAuditQuery(c); err == nil {
				t.Fatalf("%s 应被拒", tc.query)
			} else if !strings.HasPrefix(err.Error(), "invalid_query:") {
				t.Fatalf("错误码应是 invalid_query:<参数>，实际 %v", err)
			}
		})
	}
	// 合法输入要能过：逗号分隔与重复参数两种写法都认。
	c, _ := gin.CreateTestContext(nil)
	c.Request = httptest.NewRequest("GET", "/api/admin/audit-logs?service=auth,catalog&action=user.role_changed&action=settings.updated&per_page=2&page=3", nil)
	q, err := parseAuditQuery(c)
	if err != nil {
		t.Fatalf("合法查询被拒：%v", err)
	}
	if len(q.Services) != 2 || len(q.Actions) != 2 || q.Page != 3 || q.PerPage != 2 {
		t.Fatalf("解析结果不对：%#v", q)
	}
}

// 读取面的分档收敛（不建库）：无 auth.audit.read 者只能读自己，跨用户过滤一律 403。
func TestScopeAuditQueryConfinesNonPrivilegedCallers(t *testing.T) {
	const selfID = "11111111-1111-1111-1111-111111111111"
	const otherID = "22222222-2222-2222-2222-222222222222"

	scoped := func(u *store.User, query string) (store.AuditQuery, error) {
		c, _ := gin.CreateTestContext(nil)
		c.Request = httptest.NewRequest("GET", "/api/admin/audit-logs?"+query, nil)
		if u != nil {
			c.Set(userKey, u)
		}
		q, err := parseAuditQuery(c)
		if err != nil {
			t.Fatalf("%q 的查询参数应合法，不该被拒：%v", query, err)
		}
		return q, scopeAuditQuery(c, &q)
	}

	plain := &store.User{ID: selfID, Username: "bob"}
	privileged := &store.User{ID: selfID, Username: "bob", Permissions: []string{"auth.audit.read"}}
	thirdParty := &store.User{ID: selfID, Username: "bob", TokenUse: store.TokenUseOAuth}

	if _, err := scoped(nil, ""); err == nil || err.Error() != "authentication_required" {
		t.Fatalf("匿名应收敛为 authentication_required，实际 %v", err)
	}

	// 无码：收敛到自己，且不动调用者自己的其它过滤条件。
	for _, query := range []string{"", "actor_user_id=" + selfID, "action=user.profile_updated&result=failure"} {
		q, err := scoped(plain, query)
		if err != nil {
			t.Fatalf("%q 应放行，实际 %v", query, err)
		}
		if q.ActorUserID != selfID {
			t.Fatalf("%q 应被收敛到本人，实际 %q", query, q.ActorUserID)
		}
		if strings.Contains(query, "action=") && len(q.Actions) != 1 {
			t.Fatalf("%q 的 action 过滤被清掉了：%#v", query, q.Actions)
		}
		if strings.Contains(query, "result=") && q.Result != audit.ResultFailure {
			t.Fatalf("%q 的 result 过滤被清掉了：%q", query, q.Result)
		}
	}

	// 无码：指向他人、或任何前缀过滤，一律 forbidden（不静默改写）。
	for _, query := range []string{"actor_user_id=" + otherID, "actor=bob", "actor=b"} {
		if _, err := scoped(plain, query); err == nil || err.Error() != "forbidden" {
			t.Fatalf("%q 应 forbidden，实际 %v", query, err)
		}
	}

	// 第三方 OAuth 令牌：即使代表本人也拒绝——审计行是本人的安全历史。
	if _, err := scoped(thirdParty, ""); err == nil || err.Error() != "forbidden" {
		t.Fatalf("第三方令牌应 forbidden，实际 %v", err)
	}

	// 持码者：原样放行，含跨用户过滤。
	q, err := scoped(privileged, "actor_user_id="+otherID+"&actor=ali")
	if err != nil {
		t.Fatalf("持码者应放行，实际 %v", err)
	}
	if q.ActorUserID != otherID || q.ActorPrefix != "ali" {
		t.Fatalf("持码者的过滤条件不该被改写：%#v", q)
	}
}
