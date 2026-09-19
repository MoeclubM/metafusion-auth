package store

// 开发者自助审计：只读"归属自己的应用"的 oauth_audit 行。
//
// 与 ListOAuthAudits（管理台全量排障）的分工：管理台按权限码 auth.oauth.manage 看全量，
// 这里按 oauth_clients.owner_user_id 看归属——归属判定就是"当前登录身份"本身，
// 与 ListDeveloperApps / RevokeOwnOAuthGrant 同一口径（路径里没有别人的 user id）。
//
// 客户端删掉之后它的审计行不再归属任何人（owner 行随客户端消失）：INNER JOIN 会把
// 它们挡在外面——删掉的应用本来就不该出现在"我的应用审计"里；需要全量留痕去管理台查。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// OwnAppAuditEntry 是"我的应用"的一条授权审计：与 OAuthAuditEntry 同形，
// 多一个 client_name（开发者中心要展示"哪一个应用"，只给 id 认不出）。
type OwnAppAuditEntry struct {
	ID         string   `json:"id"`
	ActorID    string   `json:"actor_user_id,omitempty"`
	Actor      string   `json:"actor_username,omitempty"`
	SubjectID  string   `json:"subject_user_id,omitempty"`
	ClientID   string   `json:"client_id"`
	ClientName string   `json:"client_name"`
	Action     string   `json:"action"`
	Scopes     []string `json:"scopes"`
	Detail     string   `json:"detail,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

// ListOwnAppAudits 只读归属 ownerID 的应用的审计行，clientID 为空表示不过滤。
// limit 与 ListOAuthAudits 同口径：<=0 或 >500 时回落 100。
func (s *Store) ListOwnAppAudits(ctx context.Context, ownerID, clientID string, limit int) ([]OwnAppAuditEntry, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, fmt.Errorf("authentication_required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{ownerID}
	where := " WHERE c.owner_user_id=$1"
	if cid := strings.TrimSpace(clientID); cid != "" {
		args = append(args, cid)
		where += fmt.Sprintf(" AND a.client_id=$%d", len(args))
	}
	args = append(args, limit)
	q := "SELECT a.id, COALESCE(a.actor_user_id::text,''), COALESCE(u.username,''), COALESCE(a.subject_user_id::text,'')," +
		" a.client_id, COALESCE(c.name,''), a.action, a.scopes, a.detail, a.created_at" +
		" FROM auth.oauth_audit a LEFT JOIN auth.oauth_clients c ON c.id=a.client_id" +
		" LEFT JOIN auth.users u ON u.id=a.actor_user_id" + where + fmt.Sprintf(" ORDER BY a.created_at DESC LIMIT $%d", len(args))
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OwnAppAuditEntry{}
	for rows.Next() {
		var (
			e       OwnAppAuditEntry
			scopes  []string
			created time.Time
		)
		if err := rows.Scan(&e.ID, &e.ActorID, &e.Actor, &e.SubjectID, &e.ClientID, &e.ClientName, &e.Action, pq.Array(&scopes), &e.Detail, &created); err != nil {
			return nil, err
		}
		e.Scopes = scopes
		if e.Scopes == nil {
			e.Scopes = []string{}
		}
		e.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, e)
	}
	return out, rows.Err()
}
