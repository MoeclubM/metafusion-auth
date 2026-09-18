package store

// 审计留痕的读写支撑（读取面与"变更前"快照都在这）。
//
// 表结构不在这里建：audit schema 是跨服务共用的平台表，建表语句在 internal/audit 的 Schema
// 常量里（store.Init 会执行它），字段级契约见主仓库 docs/architecture/audit-log.md。
// 这里只负责三件事：给变更摘要拿"变更前"值、按管理台的过滤条件查、以及不把
// auth schema 的领域读取混进审计代码。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditUserSnapshot 是写审计摘要用的用户快照（含 email：它由 audit 包统一遮罩成
// j***@example.com 后才落库，这里不做脱敏——脱敏只有一个地方做）。
type AuditUserSnapshot struct {
	ID       string
	Username string
	Email    string
	Role     string
	Banned   bool
	Groups   []string
}

// AuditUserSnapshot 按 id 取用户快照。id 为空或非 uuid 返回 sql.ErrNoRows：
// 审计摘要拿不到"变更前"时应当留空，而不是让业务请求失败（调用方按这个语义处理）。
func (s *Store) AuditUserSnapshot(ctx context.Context, id string) (*AuditUserSnapshot, error) {
	if strings.TrimSpace(id) == "" {
		return nil, sql.ErrNoRows
	}
	snap := &AuditUserSnapshot{ID: id}
	err := s.DB.QueryRowContext(ctx,
		"SELECT username, email, role, banned FROM auth.users WHERE id = NULLIF($1,'')::uuid", id).
		Scan(&snap.Username, &snap.Email, &snap.Role, &snap.Banned)
	if err != nil {
		return nil, err
	}
	groups, gerr := s.GroupsForUser(ctx, id)
	if gerr != nil && gerr != sql.ErrNoRows {
		return nil, gerr
	}
	for _, g := range groups {
		snap.Groups = append(snap.Groups, g.Code)
	}
	return snap, nil
}

// AuditGroupSnapshot 按组码取权限组快照（变更前后的对比用）。组码不存在时返回 sql.ErrNoRows。
func (s *Store) AuditGroupSnapshot(ctx context.Context, code string) (*Group, error) {
	groups, err := s.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if groups[i].Code == code {
			return &groups[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

// AuditQuery 是读取面的过滤条件：字段与 GET /api/admin/audit-logs 的查询参数一一对应
// （非法值在 HTTP 层就被拒了，这里不再重复校验语义，只负责拼 SQL）。
type AuditQuery struct {
	Services    []string
	Actions     []string
	ActorUserID string
	ActorPrefix string
	TargetType  string
	TargetID    string
	Result      string
	From        *time.Time
	To          *time.Time
	RequestID   string
	Page        int
	PerPage     int
}

// AuditRow 是管理台读到的一行审计。字段名与表结构一致，便于前端与排障脚本直接对齐。
type AuditRow struct {
	ID             string         `json:"id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	Service        string         `json:"service"`
	Action         string         `json:"action"`
	ActorUserID    string         `json:"actor_user_id"`
	ActorUsername  string         `json:"actor_username"`
	CredentialType string         `json:"credential_type"`
	ActorIP        string         `json:"actor_ip"`
	ActorUserAgent string         `json:"actor_user_agent"`
	TargetType     string         `json:"target_type"`
	TargetID       string         `json:"target_id"`
	Changes        map[string]any `json:"changes"`
	Result         string         `json:"result"`
	ErrorCode      string         `json:"error_code"`
	RequestMethod  string         `json:"request_method"`
	Route          string         `json:"route"`
	HTTPStatus     int            `json:"http_status"`
	RequestID      string         `json:"request_id"`
}

// AuditPage 是分页结果：total 是过滤后的总数（前端据此显示页数），与 items 同一套条件。
type AuditPage struct {
	Items   []AuditRow `json:"items"`
	Total   int64      `json:"total"`
	Page    int        `json:"page"`
	PerPage int        `json:"per_page"`
}

// auditWhere 把过滤条件翻成 WHERE 子句与参数。多值过滤走 = ANY($n)，与手拼 IN 相比
// 少一次"参数个数随输入变化"的拼接逻辑，也不会因为值为空而生成非法 SQL。
func auditWhere(q AuditQuery) (string, []any) {
	conds := []string{}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if len(q.Services) > 0 {
		add("service = ANY($%d)", q.Services)
	}
	if len(q.Actions) > 0 {
		add("action = ANY($%d)", q.Actions)
	}
	if q.ActorUserID != "" {
		add("actor_user_id = NULLIF($%d,'')::uuid", q.ActorUserID)
	}
	if q.ActorPrefix != "" {
		// 前缀匹配，大小写不敏感：审计里存的是当时的用户名快照，运营查的是"这人干了什么"。
		add("actor_username ILIKE ($%d || '%%')", escapeLikePrefix(q.ActorPrefix))
	}
	if q.TargetType != "" {
		add("target_type = $%d", q.TargetType)
	}
	if q.TargetID != "" {
		add("target_id = $%d", q.TargetID)
	}
	if q.Result != "" {
		add("result = $%d", q.Result)
	}
	if q.From != nil {
		add("occurred_at >= $%d", *q.From)
	}
	if q.To != nil {
		add("occurred_at <= $%d", *q.To)
	}
	if q.RequestID != "" {
		add("request_id = $%d", q.RequestID)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// escapeLikePrefix 转义 ILIKE 的通配符：不转义时用户输入 "%" 会变成全表扫描。
func escapeLikePrefix(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")
	return r.Replace(s)
}

// auditColumns 与 Scan 顺序一一对应，改一处必须改另一处。
const auditColumns = "id, occurred_at, service, action, COALESCE(actor_user_id::text,''), actor_username, credential_type, " +
	"actor_ip, actor_user_agent, target_type, target_id, changes, result, error_code, " +
	"request_method, route, http_status, request_id"

// ListAuditLogs 按过滤条件分页读取审计（读取面的唯一实现）。
//
// 排序固定 occurred_at DESC, id DESC：只按时间排会在同一毫秒的多行上产生不稳定分页
// （翻页时重复/漏行），补一个 id 才能让 page/offset 语义成立。
func (s *Store) ListAuditLogs(ctx context.Context, q AuditQuery) (AuditPage, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PerPage < 1 {
		q.PerPage = 50
	}
	where, args := auditWhere(q)
	page := AuditPage{Items: []AuditRow{}, Page: q.Page, PerPage: q.PerPage}
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM audit.audit_log"+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	args = append(args, q.PerPage, (q.Page-1)*q.PerPage)
	query := "SELECT " + auditColumns + " FROM audit.audit_log" + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			item    AuditRow
			changes []byte
		)
		if err = rows.Scan(&item.ID, &item.OccurredAt, &item.Service, &item.Action, &item.ActorUserID,
			&item.ActorUsername, &item.CredentialType, &item.ActorIP, &item.ActorUserAgent,
			&item.TargetType, &item.TargetID, &changes, &item.Result, &item.ErrorCode,
			&item.RequestMethod, &item.Route, &item.HTTPStatus, &item.RequestID); err != nil {
			return page, err
		}
		item.Changes = map[string]any{}
		if len(changes) > 0 {
			// changes 是 jsonb，坏行（人手改库）不该让整个列表 500：解析失败就留空对象。
			_ = json.Unmarshal(changes, &item.Changes)
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}
