package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func (s *Store) User(ctx context.Context, token string) (*User, error) {
	h := sessionHash(token)
	var u User
	err := s.DB.QueryRowContext(ctx, "SELECT u.id,u.username,COALESCE(u.email,''),u.role FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()", h).Scan(&u.ID, &u.Username, &u.Email, &u.Role)
	if err != nil {
		err = s.DB.QueryRowContext(ctx, "SELECT u.id,u.username,COALESCE(u.email,''),u.role FROM auth.oauth_tokens t JOIN auth.users u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.expires_at>now()", h).Scan(&u.ID, &u.Username, &u.Email, &u.Role)
	}
	if err != nil {
		return &u, err
	}
	// 两条查库路径都必须补齐组与权限：访问令牌过期（AccessTokenTTL）后请求回退到这里，
	// 而 permissions 是唯一授权来源——漏掉就会让"role 仍是 user、权限全来自自定义组"的
	// 成员在令牌过期那一刻丢掉全部能力（管理台入口消失、端点 403），续期路径却还有权限。
	if err := s.WithAccess(ctx, &u); err != nil {
		return &u, err
	}
	return &u, nil
}

func (s *Store) SetupNeeded(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.users").Scan(&n)
	return n == 0, err
}

func (s *Store) CreateUser(ctx context.Context, username, email, password string, setup bool, actor *User) (User, error) {
	return s.CreateUserWithRole(ctx, username, email, password, setup, "editor", actor)
}

// CreateUserWithRole 创建指定角色的账号。setup 忽略角色直接建首个 admin；
// editor 由管理员在管理台创建；user（审核制普通用户）供将来的自助注册端点使用。
func (s *Store) CreateUserWithRole(ctx context.Context, username, email, password string, setup bool, role string, actor *User) (User, error) {
	if role != "user" && role != "editor" && role != "admin" {
		return User{}, fmt.Errorf("invalid_role")
	}
	u := User{ID: uuid.NewString(), Username: strings.TrimSpace(username), Email: strings.TrimSpace(email), Role: role}
	if u.Email == "" {
		u.Email = fmt.Sprintf("%s@findverse.cc", u.Username)
	}
	if len(u.Username) < 2 || len(u.Username) > 80 || len(password) < 12 || len(password) > 72 {
		return u, fmt.Errorf("invalid_credentials_format")
	}
	if !setup && (actor == nil || actor.Role != "admin") {
		return u, fmt.Errorf("forbidden")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return u, err
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		if setup {
			var n int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM auth.users").Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				return fmt.Errorf("setup_complete")
			}
			u.Role = "admin"
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO auth.users(id,username,email,password_hash,role) VALUES($1,$2,$3,$4,$5)", u.ID, u.Username, u.Email, string(hash), u.Role); err != nil {
			return err
		}
		for _, code := range RoleToGroups(u.Role) {
			var gid string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM auth.groups WHERE code=$1", code).Scan(&gid); err != nil {
				continue
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id,granted_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", u.ID, gid, nullableActor(actor)); err != nil {
				return err
			}
		}
		return nil
	})
	return u, err
}

// Login 校验口令，签发 RS256 访问令牌，并在服务端登记一条同哈希会话记录。
// 双模式：JWT 让后续请求无需查库；会话记录保留可吊销性与 /auth/refresh 的续期
// 依据（JWT 本身不可撤回，登出时靠 jti 注销集合 + 删除会话行）。
func (s *Store) Login(ctx context.Context, username, password string) (string, User, error) {
	var u User
	var stored string
	err := s.DB.QueryRowContext(ctx, "SELECT id,username,COALESCE(email,''),role,password_hash FROM auth.users WHERE username=$1 OR (email=$1 AND email<>'')", strings.TrimSpace(username)).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &stored)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) != nil {
		return "", u, fmt.Errorf("invalid_credentials")
	}
	// 令牌里带组与权限：下游服务本地验签即可判定能力，不必回调账号服务。
	if err := s.WithAccess(ctx, &u); err != nil {
		return "", u, err
	}
	token, _, err := s.issueSessionToken(u)
	if err != nil {
		return "", u, err
	}
	// 会话行按既有语义保留 24 小时：JWT 过期后验签失败会回退查库，
	// 这行记录就是"仍处于登录态"的事实来源，直到刷新或登出为止。
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO auth.sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", sessionHash(token), u.ID, time.Now().Add(24*time.Hour)); err != nil {
		return "", u, err
	}
	return token, u, nil
}

// issueSessionToken 在配置了签发器时返回 RS256 JWT（有效期 AccessTokenTTL），
// 否则退回随机不透明令牌（纯查库模式，保持既有行为与测试可用）。
func (s *Store) issueSessionToken(u User) (string, time.Duration, error) {
	if s.Tokens == nil {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", 0, err
		}
		return hex.EncodeToString(b), 24 * time.Hour, nil
	}
	token, _, exp, err := s.Tokens.Sign(u)
	if err != nil {
		return "", 0, err
	}
	return token, time.Until(exp), nil
}

// sessionHash 统一服务端会话的存储形式：无论令牌是 JWT 还是不透明随机串，
// 都只落 SHA-256，避免数据库泄露即等于令牌泄露。
func sessionHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *Store) Logout(ctx context.Context, token string) error {
	if s.Tokens != nil {
		s.Tokens.RevokeToken(token)
	}
	_, err := s.DB.ExecContext(ctx, "DELETE FROM auth.sessions WHERE token_hash=$1", sessionHash(token))
	return err
}

// Refresh 校验现有令牌（无状态或查库），重新签发一个新令牌并清理旧会话行。
// 用于访问令牌临近过期时的续期；refresh 本身也接受 Bearer 令牌，前端无需
// 额外的 refresh_token 字段。新令牌按库中最新身份签发：JWT 内 role 可能陈旧
// （降权后旧令牌仍能验签通过），必须回表取最新行，否则降权会被续期续接。
func (s *Store) Refresh(ctx context.Context, token string) (string, User, error) {
	u, err := s.Authenticate(ctx, token)
	if err != nil || u == nil {
		return "", User{}, fmt.Errorf("invalid_token")
	}
	var fresh User
	if ferr := s.DB.QueryRowContext(ctx, "SELECT id,username,COALESCE(email,''),role FROM auth.users WHERE id=$1", u.ID).Scan(&fresh.ID, &fresh.Username, &fresh.Email, &fresh.Role); ferr != nil {
		return "", User{}, fmt.Errorf("invalid_token")
	}
	u = &fresh
	if err := s.WithAccess(ctx, u); err != nil {
		return "", User{}, err
	}
	if s.Tokens == nil {
		return token, *u, nil // 纯查库模式无续期语义，原令牌继续有效
	}
	next, _, err := s.issueSessionToken(*u)
	if err != nil {
		return "", User{}, err
	}
	s.Tokens.RevokeToken(token)
	if _, err = s.DB.ExecContext(ctx, "DELETE FROM auth.sessions WHERE token_hash=$1", sessionHash(token)); err != nil {
		return "", User{}, err
	}
	// 与 Login 一致：会话行保留 24 小时，作为 JWT 过期后的查库兜底事实来源。
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO auth.sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", sessionHash(next), u.ID, time.Now().Add(24*time.Hour)); err != nil {
		return "", User{}, err
	}
	return next, *u, nil
}
func (s *Store) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if len(newPassword) < 12 || len(newPassword) > 72 {
		return fmt.Errorf("invalid_password_length")
	}
	var stored string
	err := s.DB.QueryRowContext(ctx, "SELECT password_hash FROM auth.users WHERE id=$1", userID).Scan(&stored)
	if err != nil {
		return fmt.Errorf("user_not_found")
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(oldPassword)) != nil {
		return fmt.Errorf("invalid_old_password")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err = s.DB.ExecContext(ctx, "UPDATE auth.users SET password_hash=$1 WHERE id=$2", string(newHash), userID); err != nil {
		return err
	}
	// 改密后作废该用户全部服务端会话与 OAuth 令牌：旧访问令牌验签成功会直接
	// 放行（15 分钟窗口），必须删会话行才能让回退查库也失效；OAuth 行 30 天有效，
	// 不删则第三方令牌继续可用。与 ResetUserPassword 行为对齐。
	if _, err = s.DB.ExecContext(ctx, "DELETE FROM auth.sessions WHERE user_id=$1", userID); err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "DELETE FROM auth.oauth_tokens WHERE user_id=$1", userID)
	return err
}

func (s *Store) LogoutAll(ctx context.Context, userID string) error {
	if _, err := s.DB.ExecContext(ctx, "DELETE FROM auth.sessions WHERE user_id=$1", userID); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, "DELETE FROM auth.oauth_tokens WHERE user_id=$1", userID)
	return err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, username, COALESCE(email,''), role FROM auth.users ORDER BY username ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.attachAccess(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// attachAccess 批量补齐用户的组与权限：一次查完全部成员关系，避免列表页 N+1 查询。
func (s *Store) attachAccess(ctx context.Context, users []User) error {
	if len(users) == 0 {
		return nil
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT ug.user_id, g.code, g.permissions FROM auth.user_groups ug JOIN auth.groups g ON g.id=ug.group_id")
	if err != nil {
		return err
	}
	defer rows.Close()
	byUser := map[string][]Group{}
	for rows.Next() {
		var uid string
		var code string
		var perms []string
		if err := rows.Scan(&uid, &code, pq.Array(&perms)); err != nil {
			return err
		}
		byUser[uid] = append(byUser[uid], Group{Code: code, Permissions: perms})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range users {
		gs := byUser[users[i].ID]
		users[i].Groups = make([]string, 0, len(gs))
		for _, g := range gs {
			users[i].Groups = append(users[i].Groups, g.Code)
		}
		users[i].Permissions = ExpandPermissions(gs)
	}
	return nil
}

func (s *Store) UpdateUserRole(ctx context.Context, targetUserID, newRole string, actor *User) error {
	if actor == nil || actor.Role != "admin" {
		return fmt.Errorf("forbidden")
	}
	if newRole != "admin" && newRole != "editor" && newRole != "user" {
		return fmt.Errorf("invalid_role")
	}
	if actor.ID == targetUserID && newRole != "admin" {
		var adminCount int
		if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.users WHERE role='admin'").Scan(&adminCount); err != nil {
			return err
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot_demote_sole_admin")
		}
	}
	// 角色与组同步：历史角色映射到等价组，避免"改了角色但权限没变"的双轨漂移。
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE auth.users SET role=$1 WHERE id=$2", newRole, targetUserID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("user_not_found")
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM auth.user_groups WHERE user_id=$1", targetUserID); err != nil {
			return err
		}
		for _, code := range RoleToGroups(newRole) {
			var gid string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM auth.groups WHERE code=$1", code).Scan(&gid); err != nil {
				continue
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth.user_groups(user_id,group_id,granted_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", targetUserID, gid, actor.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ResetUserPassword(ctx context.Context, targetUserID, newPassword string, actor *User) error {
	if actor == nil || actor.Role != "admin" {
		return fmt.Errorf("forbidden")
	}
	if len(newPassword) < 12 || len(newPassword) > 72 {
		return fmt.Errorf("invalid_password_length")
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE auth.users SET password_hash=$1 WHERE id=$2", string(newHash), targetUserID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user_not_found")
	}
	_, _ = s.DB.ExecContext(ctx, "DELETE FROM auth.sessions WHERE user_id=$1", targetUserID)
	_, _ = s.DB.ExecContext(ctx, "DELETE FROM auth.oauth_tokens WHERE user_id=$1", targetUserID)
	return nil
}
