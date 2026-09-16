// Package store 拥有账号数据：用户、会话、OAuth 客户端与授权码/令牌。
// 数据全部落在 auth schema，与目录库（catalog schema）不建外键，只保留裸 UUID 引用。
package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// User 是账号的对外投影；password_hash 永不出现在 JSON 里。
//
// Groups/Permissions 是权限组的投影：Groups 是组码，Permissions 是展开后的权限码集合。
// 两者随 /auth/me 与访问令牌下发，各子系统据此判定自己的能力；role 是历史兼容字段
// （admin/editor/user），由组成员关系推导，保留给尚未接入权限码的旧代码。
type User struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Groups      []string `json:"groups,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// Store 组合数据库与令牌签发器：签发器为 nil 时退化为纯查库模式，
// 便于在没有配置 RSA 私钥的环境里仍能启动（令牌不可用但不静默放行）。
type Store struct {
	DB     *sql.DB
	Tokens *TokenIssuer
}

// schema 与主仓库 backend/internal/catalog/schema.sql 的 auth 部分同一定义，
// 幂等；账号服务自己保证首次启动即可用，不依赖目录服务的初始化顺序。
const schema = `
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (
 id uuid PRIMARY KEY, username text NOT NULL UNIQUE, email text NOT NULL DEFAULT '', password_hash text NOT NULL,
 role text NOT NULL CHECK (role IN ('user','editor','admin'))
);
ALTER TABLE auth.users ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS auth.sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES auth.users(id), expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS auth.oauth_clients (
 id text PRIMARY KEY, secret_hash text NOT NULL, name text NOT NULL,
 redirect_uris text[] NOT NULL DEFAULT '{}', trusted boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);
-- 客户端的 scope 白名单：授权时收敛成「这份白名单 ∩ 请求」。老行按默认值补齐三种 scope，
-- 保持拆分前"不传 scope 也拿到 profile"的行为不变。
ALTER TABLE auth.oauth_clients ADD COLUMN IF NOT EXISTS scopes text[] NOT NULL DEFAULT '{openid,profile,email}';
-- 停用的客户端不能再发起授权、也不能用已有令牌取用户信息（行还在，但不可用）。
ALTER TABLE auth.oauth_clients ADD COLUMN IF NOT EXISTS disabled boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS auth.oauth_codes (
 code text PRIMARY KEY, client_id text NOT NULL REFERENCES auth.oauth_clients(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 redirect_uri text NOT NULL, scope text NOT NULL DEFAULT 'profile',
 expires_at timestamptz NOT NULL, used boolean NOT NULL DEFAULT false
);
ALTER TABLE auth.oauth_codes ADD COLUMN IF NOT EXISTS code_challenge text NOT NULL DEFAULT '';
ALTER TABLE auth.oauth_codes ADD COLUMN IF NOT EXISTS code_challenge_method text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS auth.oauth_tokens (
 token_hash text PRIMARY KEY, client_id text NOT NULL REFERENCES auth.oauth_clients(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 scope text NOT NULL DEFAULT 'profile', expires_at timestamptz NOT NULL
);
-- 签发时的 jti：吊销整批令牌时用它把已签发的无状态 JWT 在本进程内立即作废
-- （库里只有哈希，没有 jti 就无法把"批量的行"映射回令牌）。
ALTER TABLE auth.oauth_tokens ADD COLUMN IF NOT EXISTS jti text NOT NULL DEFAULT '';
-- OAuth 审计：同意/拒绝与客户端管理动作。client_id 故意不建外键——客户端删掉之后
-- 这份记录必须还在，否则审计就失去意义。
CREATE TABLE IF NOT EXISTS auth.oauth_audit (
 id uuid PRIMARY KEY, actor_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
 subject_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
 client_id text NOT NULL DEFAULT '', action text NOT NULL,
 scopes text[] NOT NULL DEFAULT '{}', detail text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now()
);
-- 角色取值与主仓库迁移 000010 的终态对齐：早期库只有 editor/admin 两值，
-- 会让管理台把角色设成 user 时失败。这里只放宽取值集合，不会让既有数据失效。
ALTER TABLE auth.users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE auth.users ADD CONSTRAINT users_role_check CHECK (role IN ('user','editor','admin'));
-- 实例设置：注册开关、邀请码强度、限流参数等。键值对存放，未知键由应用层拒绝。
CREATE TABLE IF NOT EXISTS auth.instance_settings (
 key text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
-- 邀请码：可限次、可过期、可吊销；invite_uses 记录"谁用哪个码进来的"。
CREATE TABLE IF NOT EXISTS auth.invites (
 code text PRIMARY KEY, created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
 note text NOT NULL DEFAULT '', max_uses int NOT NULL DEFAULT 1 CHECK (max_uses > 0),
 used_count int NOT NULL DEFAULT 0 CHECK (used_count >= 0),
 revoked boolean NOT NULL DEFAULT false, expires_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth.invite_uses (
 invite_code text NOT NULL REFERENCES auth.invites(code) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 used_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (invite_code, user_id)
);
-- 权限组：一份权限码集合 + 四语名。权限码的含义由各子系统自己解释（见 access.go 注释）。
CREATE TABLE IF NOT EXISTS auth.groups (
 id uuid PRIMARY KEY, code text NOT NULL UNIQUE CHECK (code ~ '^[a-z][a-z0-9_-]{1,63}$'),
 names jsonb NOT NULL DEFAULT '{}'::jsonb, descriptions jsonb NOT NULL DEFAULT '{}'::jsonb,
 permissions text[] NOT NULL DEFAULT '{}', is_system boolean NOT NULL DEFAULT false,
 sort_order int NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth.user_groups (
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 group_id uuid NOT NULL REFERENCES auth.groups(id) ON DELETE CASCADE,
 granted_by uuid, granted_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (user_id, group_id)
);
`

// seedClients 是第一方 OAuth 客户端的种子：这三个客户端原先由目录服务在启动时写入
// （`schema.sql` + `Store.Initialize`）。账号拆出后 auth schema 归本服务所有，
// 种子随之搬到这里，目录侧不再往这个 schema 写任何一行。
//
// 语义与迁移过来的那份逐字一致：secret_hash 为空表示"受信任的第一方，允许无密钥"，
// redirect_uris 覆盖线上域名与本地开发端口，ON CONFLICT 保护后台改过的配置不被覆盖。
const seedClients = `
INSERT INTO auth.oauth_clients(id, secret_hash, name, redirect_uris, trusted)
VALUES
 ('metafusion-resources', '', 'MetaFusion 资源存储与下载管理中心', ARRAY['https://resources.findverse.cc/callback', 'http://localhost:3001/callback'], true),
 ('metafusion-forum', '', 'MetaFusion 社区论坛', ARRAY['https://forum.findverse.cc/auth/oauth2_basic/callback', 'http://localhost:4200/auth/callback'], true),
 ('metafusion-catalog', '', 'MetaFusion 元数据知识库', ARRAY['https://findverse.cc/auth/callback', 'http://localhost:3000/auth/callback'], true)
ON CONFLICT (id) DO NOTHING;`

func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) Init(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, schema); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx, seedClients); err != nil {
		return err
	}
	return s.seedGroups(ctx)
}

// Authenticate 是账号校验的唯一入口：无状态 RS256 验签优先，失败回退查库。
// 回退路径保证存量不透明会话令牌（登录时写入 auth.sessions 的那份）仍然有效，
// 也让"登出即失效"这类需要服务端状态的操作可以立即生效。
func (s *Store) Authenticate(ctx context.Context, token string) (*User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, sql.ErrNoRows
	}
	if s.Tokens != nil {
		if claims, err := s.Tokens.Verify(token); err == nil {
			return ClaimsToUser(claims), nil
		}
	}
	return s.User(ctx, token)
}

// write 在事务内执行写入。取一个账号服务专属的事务级 advisory 锁（740203），
// 让"仅首个管理员可初始化"这类先查后写判定在并发下不会双开；
// 与目录服务的写入锁（740202）分开，两个服务之间不互相阻塞。
func (s *Store) write(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(740203)"); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ErrForbidden 供 HTTP 层区分 403 与 400。
var ErrForbidden = errors.New("forbidden")
