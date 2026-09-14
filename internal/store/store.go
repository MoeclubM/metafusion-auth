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
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
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
-- 角色取值与主仓库迁移 000010 的终态对齐：早期库只有 editor/admin 两值，
-- 会让管理台把角色设成 user 时失败。这里只放宽取值集合，不会让既有数据失效。
ALTER TABLE auth.users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE auth.users ADD CONSTRAINT users_role_check CHECK (role IN ('user','editor','admin'));
`

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
	_, err := s.DB.ExecContext(ctx, schema)
	return err
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
