package handler

// 账号服务的审计留痕接线：动作码注册表（写路由 → 稳定机器码）、豁免表、中间件与读取面。
//
// 设计见主仓库 docs/architecture/audit-log.md：审计是旁路（落库失败不影响业务），
// 只有登记过的写路由才留痕，新增写端点忘了登记会被 audit_routes_test.go 的覆盖守卫拦住。

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MoeclubM/metafusion-auth/internal/audit"
	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// auditActions 是「HTTP 方法 + 路由模板」→ 动作码。路由模板用 gin 的 FullPath 形状
// （/api/admin/users/:id/role），不是请求里的真实路径。
//
// 动作码只增不改：改名等于把历史记录切成两段，聚合查询会断。
func auditActions() map[string]string {
	return map[string]string{
		"POST /api/setup":                                 "setup.completed",
		"POST /api/auth/login":                            "session.login",
		"POST /api/auth/logout":                           "session.logged_out",
		"POST /api/auth/register":                         "session.registered",
		"POST /api/auth/logout-all":                       "user.sessions_revoked",
		"PUT /api/auth/password":                          "user.password_changed",
		"PUT /api/auth/profile":                           "user.profile_updated",
		"POST /api/auth/invite":                           "invite.self_created",
		"DELETE /api/auth/oauth-grants/:client_id":        "user.oauth_grant_revoked",
		"POST /api/auth/tokens":                           "pat.created",
		"DELETE /api/auth/tokens/:id":                     "pat.revoked",
		"PUT /api/admin/settings":                         "settings.updated",
		"POST /api/admin/invites":                         "invite.created",
		"POST /api/admin/invites/:code/revoke":            "invite.revoked",
		"POST /api/admin/groups":                          "group.created",
		"PUT /api/admin/groups/:code":                     "group.updated",
		"DELETE /api/admin/groups/:code":                  "group.deleted",
		"POST /api/admin/users":                           "user.created",
		"PUT /api/admin/users/:id/role":                   "user.role_changed",
		"PUT /api/admin/users/:id/password":               "user.password_reset",
		"PUT /api/admin/users/:id/ban":                    "user.banned",
		"PUT /api/admin/users/:id/groups":                 "user.groups_changed",
		"POST /api/admin/users/:id/revoke-oauth-tokens":   "user.oauth_tokens_revoked",
		"POST /api/admin/oauth/clients":                   "oauth_client.created",
		"PUT /api/admin/oauth/clients/:id":                "oauth_client.updated",
		"POST /api/admin/oauth/clients/:id/rotate-secret": "oauth_client.secret_rotated",
		"DELETE /api/admin/oauth/clients/:id":             "oauth_client.deleted",
		"POST /api/admin/oauth/clients/:id/revoke-tokens": "oauth_client.tokens_revoked",
		"POST /api/developer/apps":                        "oauth_client.self_registered",
		"PUT /api/developer/apps/:id":                     "oauth_client.self_updated",
		"POST /api/developer/apps/:id/rotate-secret":      "oauth_client.self_secret_rotated",
		"DELETE /api/developer/apps/:id":                  "oauth_client.self_deleted",
	}
}

// auditExempt 是写路由的豁免表：route → 理由。运行时不用它（豁免的路由干脆不登记），
// 它的唯一读者是覆盖守卫测试——把「为什么这条写路由不审计」与注册表放在一起，
// 改的时候一眼能看见，也逼着每一处豁免都必须写理由。
func auditExempt() map[string]string {
	return map[string]string{
		"POST /api/auth/refresh":           "会话续期：只延长现有会话、不改变任何状态；登录已有 session.login 留痕，续期会把审计冲成噪声",
		"POST /api/auth/tokens/introspect": "下游鉴权用的内省：读语义、无状态变更（last_used_at 是访问痕迹，不是管理动作）",
		"POST /api/oauth/token":            "OAuth 子域已有事务内的 auth.oauth_audit（授权码兑换与同意都在那里），本轮不双写",
		// 下面这条不是写方法（进不了覆盖守卫的枚举）：登记它是为了让"同意页也会落库"这件事
		// 在豁免表里留下一句理由，而不是靠读者自己发现。
		"GET /api/oauth/authorize": "同意/拒绝会写授权码，是 GET 上的写副作用；已由事务内的 auth.oauth_audit 留痕，本轮不双写",
	}
}

// auditMiddleware 是本服务的审计中间件：身份解析在 c.Next() 之后做（登录/注册/改自己密码
// 这些端点要等处理器跑完才知道操作者是谁），处理器可用 audit.SetActor 覆盖。
func (h *Handler) auditMiddleware() gin.HandlerFunc {
	return audit.Middleware(audit.Options{
		Recorder: h.audit,
		Actions:  auditActions(),
		Exempt:   auditExempt(),
		Actor:    h.auditActor,
	})
}

// auditActor 解析当前请求的操作者。
//
// credential_type 只能给 session / anonymous：本服务签发的会话令牌与 OAuth 访问令牌是同密钥、
// 同声明的 RS256 JWT（见 store.signOAuthToken），仅凭令牌内容区分不了，要区分就得在每个写请求上
// 多查一次 auth.oauth_tokens——不值得。PAT 也不会出现在这里：PAT 不是登录态，/api/auth/* 一律
// 不受理（见 pat.go 包注释）。契约文档已按实际能力修正。
func (h *Handler) auditActor(c *gin.Context) audit.Actor {
	u := currentUser(c)
	if u == nil {
		return audit.Actor{CredentialType: audit.CredentialAnonymous}
	}
	return audit.Actor{UserID: u.ID, Username: u.Username, CredentialType: audit.CredentialSession}
}

// auditUserChanges 把用户快照翻成变更摘要的 before/after 片段。email 原样交给 audit 包，
// 由它统一遮罩（不要在这一层自己拼遮罩串：两个地方脱敏就会有两套口径）。
func auditUserChanges(before *store.AuditUserSnapshot) map[string]any {
	if before == nil {
		return map[string]any{}
	}
	return map[string]any{
		"username": before.Username,
		"email":    before.Email,
		"role":     before.Role,
		"banned":   before.Banned,
		"groups":   before.Groups,
	}
}

// settingsChanges 只记"这次请求碰过的键"的 before/after：整份设置快照会让一条审计行
// 塞进整个设置表，改了哪个键反而看不见。
func settingsChanges(before, after, patch map[string]any) map[string]any {
	out := map[string]any{}
	for key := range patch {
		out[key] = map[string]any{"before": before[key], "after": after[key]}
	}
	return out
}

// groupChanges 把权限组快照翻成 before/after 片段；一侧为 nil 表示新增或删除。
func groupChanges(before, after *store.Group) map[string]any {
	snapshot := func(g *store.Group) any {
		if g == nil {
			return nil
		}
		return map[string]any{
			"code": g.Code, "names": g.Names, "descriptions": g.Descriptions,
			"permissions": g.Permissions, "sort_order": g.SortOrder, "is_system": g.IsSystem,
		}
	}
	out := map[string]any{"before": snapshot(before), "after": snapshot(after)}
	if after != nil {
		out["code"] = after.Code
	} else if before != nil {
		out["code"] = before.Code
	}
	return out
}

// usernameOf 取快照里的用户名（快照可能因为对象不存在而为 nil）。
func usernameOf(snap *store.AuditUserSnapshot) string {
	if snap == nil {
		return ""
	}
	return snap.Username
}

// appChanges 把开发者中心的应用快照翻成 before/after 片段（一侧为 nil 表示新增或删除）。
// 不含 secret_hash：它是 bcrypt 哈希，属于凭据材料。
func appChanges(snapshots ...*store.DeveloperApp) map[string]any {
	return map[string]any{"before": developerAppSnapshot(snapshots[0]), "after": developerAppSnapshot(snapshots[1])}
}

func developerAppSnapshot(app *store.DeveloperApp) any {
	if app == nil {
		return nil
	}
	return map[string]any{
		"client_id": app.ID, "name": app.Name, "description": app.Description,
		"homepage_url": app.HomepageURL, "redirect_uris": app.RedirectURIs, "scopes": app.Scopes,
		"verified": app.Verified, "disabled": app.Disabled, "has_secret": app.HasSecret,
	}
}

// oauthClientChanges 与 appChanges 同形：管理面的客户端多一个 trusted 字段。
func oauthClientChanges(snapshots ...*store.OAuthClient) map[string]any {
	return map[string]any{"before": oauthClientSnapshot(snapshots[0]), "after": oauthClientSnapshot(snapshots[1])}
}

func oauthClientSnapshot(client *store.OAuthClient) any {
	if client == nil {
		return nil
	}
	return map[string]any{
		"client_id": client.ID, "name": client.Name, "description": client.Description,
		"homepage_url": client.HomepageURL, "redirect_uris": client.RedirectURIs, "scopes": client.Scopes,
		"trusted": client.Trusted, "disabled": client.Disabled, "verified": client.Verified,
	}
}

// registerAudit 挂载审计读取面：GET /api/admin/audit-logs（唯一读取端点，见契约 §5）。
func (h *Handler) registerAudit(api *gin.RouterGroup) {
	api.GET("/admin/audit-logs", requirePermission("auth.audit.read"), func(c *gin.Context) {
		q, err := parseAuditQuery(c)
		if err != nil {
			respond(c, nil, err)
			return
		}
		page, err := h.store.ListAuditLogs(c.Request.Context(), q)
		respond(c, page, err)
	})
}

// parseAuditQuery 解析并校验读取面的查询参数。非法值一律 400 invalid_query:<参数>，
// 不做静默回落：把非法 page 当成 page=1 会让分页脚本悄悄读到第一页还以为翻页成功。
func parseAuditQuery(c *gin.Context) (store.AuditQuery, error) {
	q := store.AuditQuery{
		Services:    splitMulti(c.QueryArray("service")),
		Actions:     splitMulti(c.QueryArray("action")),
		ActorUserID: strings.TrimSpace(c.Query("actor_user_id")),
		ActorPrefix: strings.TrimSpace(c.Query("actor")),
		TargetType:  strings.TrimSpace(c.Query("target_type")),
		TargetID:    strings.TrimSpace(c.Query("target_id")),
		Result:      strings.TrimSpace(c.Query("result")),
		RequestID:   strings.TrimSpace(c.Query("request_id")),
		Page:        1,
		PerPage:     50,
	}
	if q.ActorUserID != "" {
		if _, err := uuid.Parse(q.ActorUserID); err != nil {
			return q, fmt.Errorf("invalid_query: actor_user_id")
		}
	}
	if q.Result != "" && q.Result != audit.ResultSuccess && q.Result != audit.ResultFailure {
		return q, fmt.Errorf("invalid_query: result")
	}
	for _, filter := range []struct {
		name  string
		value string
	}{{"actor", q.ActorPrefix}, {"target_type", q.TargetType}, {"target_id", q.TargetID}, {"request_id", q.RequestID}} {
		if len(filter.value) > 200 {
			return q, fmt.Errorf("invalid_query: %s", filter.name)
		}
	}
	if raw := strings.TrimSpace(c.Query("page")); raw != "" {
		page, err := strconv.Atoi(raw)
		if err != nil || page < 1 || page > maxAuditPage {
			return q, fmt.Errorf("invalid_query: page")
		}
		q.Page = page
	}
	if raw := strings.TrimSpace(c.Query("per_page")); raw != "" {
		perPage, err := strconv.Atoi(raw)
		if err != nil || perPage < 1 || perPage > maxAuditPerPage {
			return q, fmt.Errorf("invalid_query: per_page")
		}
		q.PerPage = perPage
	}
	for _, filter := range []struct {
		name  string
		value string
		dst   **time.Time
	}{{"from", c.Query("from"), &q.From}, {"to", c.Query("to"), &q.To}} {
		raw := strings.TrimSpace(filter.value)
		if raw == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return q, fmt.Errorf("invalid_query: %s", filter.name)
		}
		*filter.dst = &ts
	}
	if q.From != nil && q.To != nil && q.To.Before(*q.From) {
		return q, fmt.Errorf("invalid_query: to")
	}
	return q, nil
}

// maxAuditPerPage 是读取面的页大小上限：审计行带 changes，一次拉太多会拖住账号服务。
const maxAuditPerPage = 200

// maxAuditPage 是页码上限：它本身没有语义上限，但要把超大 offset 挡在库外
// （int 溢出会生成负数 OFFSET；审计表迟早很大，翻到第 100 万页没有意义）。
const maxAuditPage = 1_000_000

// splitMulti 支持同名单值与逗号分隔两种写法（service=a&service=b 或 service=a,b）。
func splitMulti(values []string) []string {
	out := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || len(part) > 100 {
				continue
			}
			out = append(out, part)
		}
	}
	return out
}
