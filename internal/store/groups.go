package store

// 权限组、成员分配、邀请码与自助注册。

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Group 是权限组：一份权限码集合 + 四语显示名。组码与权限码都由账号服务保管，
// 但"这个码能干什么"由各子系统自己解释。
type Group struct {
	ID           string            `json:"id"`
	Code         string            `json:"code"`
	Names        map[string]string `json:"names"`
	Descriptions map[string]string `json:"descriptions,omitempty"`
	Permissions  []string          `json:"permissions"`
	IsSystem     bool              `json:"is_system"`
	SortOrder    int               `json:"sort_order"`
}

// Invite 是邀请码：可由管理员或持有 auth.invites.manage 的成员签发，
// 支持次数上限与过期时间；`invite_required` 打开时注册必须带有效码。
type Invite struct {
	Code      string `json:"code"`
	CreatedBy string `json:"created_by"`
	Creator   string `json:"creator,omitempty"`
	Note      string `json:"note"`
	MaxUses   int    `json:"max_uses"`
	UsedCount int    `json:"used_count"`
	Revoked   bool   `json:"revoked"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at"`
}

const groupColumns = `id,code,names,descriptions,permissions,is_system,sort_order`

func scanGroups(rows *sql.Rows) ([]Group, error) {
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		var names, descs []byte
		if err := rows.Scan(&g.ID, &g.Code, &names, &descs, pq.Array(&g.Permissions), &g.IsSystem, &g.SortOrder); err != nil {
			return nil, err
		}
		g.Names = decodeNames(names)
		g.Descriptions = decodeNames(descs)
		out = append(out, g)
	}
	return out, rows.Err()
}

func decodeNames(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	_ = jsonUnmarshal(raw, &out)
	return out
}

// ListGroups 返回全部权限组（按 sort_order、code 排序），供管理台与分配界面使用。
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+groupColumns+" FROM auth.groups ORDER BY sort_order, code")
	if err != nil {
		return nil, err
	}
	return scanGroups(rows)
}

// GroupsForUser 读取某人所属的组（含权限码）。
func (s *Store) GroupsForUser(ctx context.Context, userID string) ([]Group, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+groupColumns+" FROM auth.groups g JOIN auth.user_groups ug ON ug.group_id=g.id WHERE ug.user_id=$1 ORDER BY g.sort_order, g.code", userID)
	if err != nil {
		return nil, err
	}
	return scanGroups(rows)
}

func groupsForWith(ctx context.Context, q queryer, userID string) ([]Group, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+groupColumns+" FROM auth.groups g JOIN auth.user_groups ug ON ug.group_id=g.id WHERE ug.user_id=$1 ORDER BY g.sort_order, g.code", userID)
	if err != nil {
		return nil, err
	}
	return scanGroups(rows)
}

// WithAccess 补齐用户的组与权限集合：/auth/me、令牌签发、下游服务都据此判定。
func (s *Store) WithAccess(ctx context.Context, u *User) error {
	if u == nil || u.ID == "" {
		return nil
	}
	groups, err := s.GroupsForUser(ctx, u.ID)
	if err != nil {
		return err
	}
	u.Groups = make([]string, 0, len(groups))
	for _, g := range groups {
		u.Groups = append(u.Groups, g.Code)
	}
	u.Permissions = ExpandPermissions(groups)
	return nil
}

// CreateGroup 新建权限组。管理台可以自由增删组（系统组除外，见 DeleteGroup）。
func (s *Store) CreateGroup(ctx context.Context, in Group, actor *User) (Group, error) {
	if !Can(actor, "auth.groups.manage") {
		return Group{}, fmt.Errorf("forbidden")
	}
	code := strings.TrimSpace(in.Code)
	if !ValidGroupCode(code) {
		return Group{}, fmt.Errorf("invalid_group_code")
	}
	if err := validatePermissionCodes(in.Permissions); err != nil {
		return Group{}, err
	}
	g := Group{ID: uuid.NewString(), Code: code, Names: in.Names, Descriptions: in.Descriptions, Permissions: in.Permissions, SortOrder: in.SortOrder}
	if len(g.Names) == 0 {
		g.Names = map[string]string{"zh-CN": code, "en-US": code}
	}
	if g.Permissions == nil {
		g.Permissions = []string{}
	}
	names, _ := jsonMarshal(g.Names)
	descs, _ := jsonMarshal(g.Descriptions)
	err := s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO auth.groups(id,code,names,descriptions,permissions,is_system,sort_order) VALUES($1,$2,$3,$4,$5,false,$6)", g.ID, g.Code, names, descs, pq.Array(g.Permissions), g.SortOrder)
		return err
	})
	return g, err
}

// UpdateGroup 按组码更新名称/权限/排序。系统组的权限可以改（管理员可能想调整），
// 但 admin 组的 * 权限不可移除（否则会把自己锁死在门外，见下方校验）。
func (s *Store) UpdateGroup(ctx context.Context, code string, in Group, actor *User) (Group, error) {
	if !Can(actor, "auth.groups.manage") {
		return Group{}, fmt.Errorf("forbidden")
	}
	if err := validatePermissionCodes(in.Permissions); err != nil {
		return Group{}, err
	}
	if strings.TrimSpace(code) == "admin" && !HasPermission(in.Permissions, "*") {
		return Group{}, fmt.Errorf("cannot_strip_admin_wildcard")
	}
	names, _ := jsonMarshal(in.Names)
	descs, _ := jsonMarshal(in.Descriptions)
	var out Group
	err := s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE auth.groups SET names=$1, descriptions=$2, permissions=$3, sort_order=$4 WHERE code=$5", names, descs, pq.Array(in.Permissions), in.SortOrder, strings.TrimSpace(code))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("group_not_found")
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+groupColumns+" FROM auth.groups WHERE code=$1", strings.TrimSpace(code))
		if err != nil {
			return err
		}
		list, err := scanGroups(rows)
		if err != nil || len(list) == 0 {
			return fmt.Errorf("group_not_found")
		}
		out = list[0]
		return nil
	})
	return out, err
}

// DeleteGroup 删除权限组：系统组不可删（它们承载"注册默认组""管理员"这类语义）。
func (s *Store) DeleteGroup(ctx context.Context, code string, actor *User) error {
	if !Can(actor, "auth.groups.manage") {
		return fmt.Errorf("forbidden")
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var isSystem bool
		if err := tx.QueryRowContext(ctx, "SELECT is_system FROM auth.groups WHERE code=$1", strings.TrimSpace(code)).Scan(&isSystem); err != nil {
			return fmt.Errorf("group_not_found")
		}
		if isSystem {
			return fmt.Errorf("system_group_immutable")
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM auth.groups WHERE code=$1", strings.TrimSpace(code))
		return err
	})
}

// SetUserGroups 覆盖式设置某人的组（成员分配的唯一入口）。
// 护栏：不能把最后一个管理员移出 admin 组，否则实例将失去管理入口。
func (s *Store) SetUserGroups(ctx context.Context, userID string, codes []string, actor *User) error {
	if !Can(actor, "auth.users.manage") {
		return fmt.Errorf("forbidden")
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, "SELECT true FROM auth.users WHERE id=$1", userID).Scan(&exists); err != nil {
			return fmt.Errorf("user_not_found")
		}
		keepAdmin := false
		for _, c := range codes {
			if strings.TrimSpace(c) == "admin" {
				keepAdmin = true
			}
		}
		if !keepAdmin {
			var isAdmin bool
			_ = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM auth.user_groups ug JOIN auth.groups g ON g.id=ug.group_id WHERE ug.user_id=$1 AND g.code='admin')", userID).Scan(&isAdmin)
			if isAdmin {
				var admins int
				if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM auth.user_groups ug JOIN auth.groups g ON g.id=ug.group_id WHERE g.code='admin'").Scan(&admins); err != nil {
					return err
				}
				if admins <= 1 {
					return fmt.Errorf("cannot_demote_sole_admin")
				}
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM auth.user_groups WHERE user_id=$1", userID); err != nil {
			return err
		}
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" {
				continue
			}
			var gid string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM auth.groups WHERE code=$1", code).Scan(&gid); err != nil {
				return fmt.Errorf("group_not_found: %s", code)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id,granted_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", userID, gid, actor.ID); err != nil {
				return err
			}
		}
		// role 是历史兼容字段：按组成员关系推导，让还没接入权限码的旧代码继续可用。
		return syncRoleFromGroups(ctx, tx, userID)
	})
}

// syncRoleFromGroups 依据组成员关系回写 users.role（admin > editor > user）。
func syncRoleFromGroups(ctx context.Context, tx *sql.Tx, userID string) error {
	role := "user"
	var codes []string
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(array_agg(g.code), '{}') FROM auth.groups g JOIN auth.user_groups ug ON ug.group_id=g.id WHERE ug.user_id=$1", userID).Scan(pq.Array(&codes)); err != nil {
		return err
	}
	for _, c := range codes {
		switch c {
		case "admin":
			role = "admin"
		case "catalog_editor", "catalog_admin":
			if role != "admin" {
				role = "editor"
			}
		}
	}
	_, err := tx.ExecContext(ctx, "UPDATE auth.users SET role=$1 WHERE id=$2", role, userID)
	return err
}

// RoleToGroups 是历史角色的等价组：管理台改角色时同步成员关系，两边不脱节。
func RoleToGroups(role string) []string {
	switch role {
	case "admin":
		return []string{"admin"}
	case "editor":
		return []string{"catalog_editor", "member"}
	default:
		return []string{"member"}
	}
}

// nullableActor 把可空的授权人转成 SQL NULL：setup 建立首个管理员时没有 actor。
func nullableActor(u *User) any {
	if u == nil || u.ID == "" {
		return nil
	}
	return u.ID
}

func validatePermissionCodes(codes []string) error {
	for _, c := range codes {
		if !ValidPermissionCode(c) {
			return fmt.Errorf("invalid_permission_code: %s", c)
		}
	}
	return nil
}

// ── 邀请码 ──

func (s *Store) CreateInvite(ctx context.Context, note string, maxUses int, expiresIn time.Duration, actor *User) (Invite, error) {
	if !Can(actor, "auth.invites.manage") {
		return Invite{}, fmt.Errorf("forbidden")
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if maxUses > 1000 {
		maxUses = 1000
	}
	code, err := genCode()
	if err != nil {
		return Invite{}, err
	}
	var exp any
	if expiresIn > 0 {
		exp = time.Now().Add(expiresIn)
	}
	in := Invite{Code: code, CreatedBy: actor.ID, Creator: actor.Username, Note: strings.TrimSpace(note), MaxUses: maxUses}
	err = s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO auth.invites(code,created_by,note,max_uses,expires_at) VALUES($1,$2,$3,$4,$5)", in.Code, actor.ID, in.Note, in.MaxUses, exp)
		return err
	})
	if err != nil {
		return Invite{}, err
	}
	in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if exp != nil {
		in.ExpiresAt = exp.(time.Time).UTC().Format(time.RFC3339)
	}
	return in, nil
}

// ListInvites 列出邀请码：admin 看全部，其他人只看自己签发的（管理台/个人邀请页共用）。
func (s *Store) ListInvites(ctx context.Context, actor *User) ([]Invite, error) {
	if actor == nil {
		return nil, fmt.Errorf("forbidden")
	}
	q := "SELECT i.code,i.created_by,COALESCE(u.username,''),i.note,i.max_uses,i.used_count,i.revoked,i.expires_at,i.created_at FROM auth.invites i LEFT JOIN auth.users u ON u.id=i.created_by"
	args := []any{}
	if !Can(actor, "auth.invites.manage") {
		q += " WHERE i.created_by=$1"
		args = append(args, actor.ID)
	}
	q += " ORDER BY i.created_at DESC LIMIT 200"
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Invite{}
	for rows.Next() {
		var in Invite
		var exp sql.NullTime
		var created time.Time
		if err := rows.Scan(&in.Code, &in.CreatedBy, &in.Creator, &in.Note, &in.MaxUses, &in.UsedCount, &in.Revoked, &exp, &created); err != nil {
			return nil, err
		}
		in.CreatedAt = created.UTC().Format(time.RFC3339)
		if exp.Valid {
			in.ExpiresAt = exp.Time.UTC().Format(time.RFC3339)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *Store) RevokeInvite(ctx context.Context, code string, actor *User) error {
	if !Can(actor, "auth.invites.manage") {
		return fmt.Errorf("forbidden")
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE auth.invites SET revoked=true WHERE code=$1", strings.ToUpper(strings.TrimSpace(code)))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("invite_not_found")
		}
		return nil
	})
}

// consumeInvite 在注册事务内校验并消耗一次邀请码：
// 计数用条件 UPDATE 原子完成（used_count < max_uses），并发注册不会超额。
func consumeInvite(ctx context.Context, tx *sql.Tx, code, userID string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return fmt.Errorf("invite_required")
	}
	var id string
	err := tx.QueryRowContext(ctx, "SELECT code FROM auth.invites WHERE code=$1 AND revoked=false AND (expires_at IS NULL OR expires_at>now()) AND used_count<max_uses FOR UPDATE", code).Scan(&id)
	if err != nil {
		return fmt.Errorf("invalid_invite_code")
	}
	res, err := tx.ExecContext(ctx, "UPDATE auth.invites SET used_count=used_count+1 WHERE code=$1 AND used_count<max_uses", code)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("invite_exhausted")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO auth.invite_uses(invite_code,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING", code, userID)
	return err
}

// ── 自助注册 ──

// Register 处理公开注册：受实例设置约束（registration_enabled / invite_required），
// 账号默认进 registration_default_groups（默认 member 组，无任何特权）。
// 成功即返回登录令牌，前端可直接进入登录态。
func (s *Store) Register(ctx context.Context, username, email, password, inviteCode string) (User, string, error) {
	settings, err := s.Settings(ctx)
	if err != nil {
		return User{}, "", err
	}
	if enabled, _ := settings[SettingRegistrationEnabled].(bool); !enabled {
		return User{}, "", fmt.Errorf("registration_closed")
	}
	u := User{ID: uuid.NewString(), Username: strings.TrimSpace(username), Email: strings.TrimSpace(email), Role: "user"}
	if u.Email == "" {
		u.Email = fmt.Sprintf("%s@findverse.cc", u.Username)
	}
	if len(u.Username) < 2 || len(u.Username) > 80 || len(password) < 12 || len(password) > 72 {
		return User{}, "", fmt.Errorf("invalid_credentials_format")
	}
	if strings.ContainsAny(u.Username, " \t") {
		return User{}, "", fmt.Errorf("invalid_credentials_format")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, "", err
	}
	needInvite, _ := settings[SettingInviteRequired].(bool)
	defaultGroups, _ := toStrSlice(settings[SettingRegistrationGroups])
	if len(defaultGroups) == 0 {
		defaultGroups = []string{"member"}
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM auth.users WHERE username=$1 OR (email<>'' AND lower(email)=lower($2))", u.Username, u.Email).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("username_or_email_taken")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash,role) VALUES($1,$2,$3,$4,$5)", u.ID, u.Username, u.Email, string(hash), u.Role); err != nil {
			return err
		}
		if needInvite {
			if err := consumeInvite(ctx, tx, inviteCode, u.ID); err != nil {
				return err
			}
		}
		for _, code := range defaultGroups {
			var gid string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM auth.groups WHERE code=$1", strings.TrimSpace(code)).Scan(&gid); err != nil {
				continue // 组被删掉时不让注册失败：默认组只是便利，不是硬约束
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id) VALUES($1,$2) ON CONFLICT DO NOTHING", u.ID, gid); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return User{}, "", err
	}
	if err := s.WithAccess(ctx, &u); err != nil {
		return u, "", err
	}
	token, _, err := s.issueSessionToken(u)
	if err != nil {
		return u, "", err
	}
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO auth.sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", sessionHash(token), u.ID, time.Now().Add(24*time.Hour)); err != nil {
		return u, "", err
	}
	return u, token, nil
}

// InvitedMembers 返回"由我的邀请码注册进来的人"（个人邀请页展示用）。
func (s *Store) InvitedMembers(ctx context.Context, actor *User) ([]User, error) {
	if actor == nil {
		return nil, fmt.Errorf("forbidden")
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT u.id,u.username,COALESCE(u.email,''),u.role FROM auth.invite_uses iu JOIN auth.invites i ON i.code=iu.invite_code JOIN auth.users u ON u.id=iu.user_id WHERE i.created_by=$1 ORDER BY iu.used_at DESC LIMIT 100", actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
