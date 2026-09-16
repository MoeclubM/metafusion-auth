package store

// OAuth 2.0 / OIDC 授权方的存储侧：客户端登记、授权码签发与交换、令牌签发与吊销。
//
// 与 identity.go 的分工：identity.go 管「账号自己」（用户 / 会话 / 登录 / 续期），
// 本文件管「账号对外授权」（第三方客户端与它的码 / 令牌）。两者共用 sessionHash 与 access.go 的权限码。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type OAuthClient struct {
	ID           string   `json:"client_id"`
	SecretHash   string   `json:"-"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Trusted      bool     `json:"trusted"`
	CreatedAt    string   `json:"created_at"`
}

func (s *Store) ListOAuthClients(ctx context.Context) ([]OAuthClient, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, name, redirect_uris, trusted, created_at FROM auth.oauth_clients ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []OAuthClient
	for rows.Next() {
		var c OAuthClient
		var uris []string
		var t time.Time
		if err := rows.Scan(&c.ID, &c.Name, pq.Array(&uris), &c.Trusted, &t); err != nil {
			return nil, err
		}
		c.RedirectURIs = uris
		c.CreatedAt = t.UTC().Format(time.RFC3339)
		list = append(list, c)
	}
	return list, rows.Err()
}

func (s *Store) GetOAuthClient(ctx context.Context, id string) (*OAuthClient, error) {
	var c OAuthClient
	var uris []string
	var t time.Time
	err := s.DB.QueryRowContext(ctx, "SELECT id, secret_hash, name, redirect_uris, trusted, created_at FROM auth.oauth_clients WHERE id=$1", strings.TrimSpace(id)).Scan(&c.ID, &c.SecretHash, &c.Name, pq.Array(&uris), &c.Trusted, &t)
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = uris
	c.CreatedAt = t.UTC().Format(time.RFC3339)
	return &c, nil
}

// CreateOAuthCode 签发授权码。challenge 为 PKCE code_challenge（可空），
// method 仅接受 S256/plain，其它值拒绝（避免降级绕过）。
func (s *Store) CreateOAuthCode(ctx context.Context, clientID string, userID string, redirectURI, scope, challenge, method string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)
	if scope == "" {
		scope = "profile"
	}
	challenge = strings.TrimSpace(challenge)
	method = strings.ToUpper(strings.TrimSpace(method))
	if challenge == "" {
		method = ""
	} else if method != "S256" && method != "PLAIN" {
		return "", fmt.Errorf("invalid_code_challenge_method")
	}
	_, err := s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_codes(code, client_id, user_id, redirect_uri, scope, expires_at, code_challenge, code_challenge_method) VALUES($1, $2, $3, $4, $5, $6, $7, $8)", code, clientID, userID, redirectURI, scope, time.Now().Add(10*time.Minute), challenge, method)
	return code, err
}

// verifyPKCE 按 RFC 7636 校验 verifier：S256 比较 BASE64URL(SHA256(verifier))，
// plain 直接比对。存量无 challenge 的码视为公开客户端历史行为，不强制。
func verifyPKCE(method, challenge, verifier string) bool {
	if challenge == "" {
		return true
	}
	verifier = strings.TrimSpace(verifier)
	if verifier == "" {
		return false
	}
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return challenge == base64.RawURLEncoding.EncodeToString(sum[:])
	case "PLAIN", "plain":
		return challenge == verifier
	default:
		return false
	}
}

func (s *Store) ExchangeOAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (string, *User, error) {
	client, err := s.GetOAuthClient(ctx, clientID)
	if err != nil || client == nil {
		return "", nil, fmt.Errorf("invalid_client")
	}
	if client.SecretHash != "" {
		if clientSecret == "" || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)) != nil {
			return "", nil, fmt.Errorf("invalid_client_secret")
		}
	} else if !client.Trusted {
		// 无密钥的非受信客户端一律拒绝：空密钥只能是预置受信第一方，
		// 且第一方也应尽快配置密钥或改走 PKCE。
		return "", nil, fmt.Errorf("invalid_client_secret")
	}
	var userID string
	var codeURI string
	var scope string
	var challenge, challengeMethod string
	// 先读码并完成全部校验，再原子标记已用：PKCE/redirect 校验失败**不得消耗**
	// 授权码，否则一次错误 verifier 请求即可作废合法客户端刚拿到的码。
	// 单次性由下方条件 UPDATE 保证：并发双兑只有一个成功，后到者按未命中
	// 拿到 expired_or_used_code。
	err = s.DB.QueryRowContext(ctx, "SELECT user_id, redirect_uri, scope, COALESCE(code_challenge,''), COALESCE(code_challenge_method,'') FROM auth.oauth_codes WHERE code=$1 AND client_id=$2 AND used=false AND expires_at>now()", strings.TrimSpace(code), clientID).Scan(&userID, &codeURI, &scope, &challenge, &challengeMethod)
	if err != nil {
		return "", nil, fmt.Errorf("expired_or_used_code")
	}
	if redirectURI != "" && redirectURI != codeURI {
		return "", nil, fmt.Errorf("redirect_uri_mismatch")
	}
	if !verifyPKCE(challengeMethod, challenge, verifier) {
		return "", nil, fmt.Errorf("invalid_code_verifier")
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE auth.oauth_codes SET used=true WHERE code=$1 AND client_id=$2 AND used=false AND expires_at>now()", strings.TrimSpace(code), clientID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid_grant")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", nil, fmt.Errorf("expired_or_used_code")
	}
	var u User
	if err = s.DB.QueryRowContext(ctx, "SELECT id, username, COALESCE(email,''), role FROM auth.users WHERE id=$1", userID).Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
		return "", nil, err
	}
	// 签发 OIDC access_token：配置签发器时为 RS256 JWT（可被 JWKS 本地验签），
	// 否则退回不透明随机串。无论哪种都只落 SHA-256 以便吊销。
	token, _, _, err := s.signOAuthToken(u)
	if err != nil {
		return "", nil, err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_tokens(token_hash, client_id, user_id, scope, expires_at) VALUES($1, $2, $3, $4, $5)", sessionHash(token), clientID, userID, scope, time.Now().Add(30*24*time.Hour))
	if err != nil {
		return "", nil, err
	}
	return token, &u, nil
}

// signOAuthToken 为 OAuth/OIDC 流程签发访问令牌：有签发器用 RS256 JWT，
// 否则用 32 字节随机串。返回令牌与其有效期（用于响应 expires_in）。
func (s *Store) signOAuthToken(u User) (string, time.Duration, int64, error) {
	if s.Tokens == nil {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", 0, 0, err
		}
		return hex.EncodeToString(b), 30 * 24 * time.Hour, 0, nil
	}
	token, _, exp, err := s.Tokens.Sign(u)
	if err != nil {
		return "", 0, 0, err
	}
	return token, time.Until(exp), exp.Unix(), nil
}

// IDToken 为 OIDC 客户端签发 id_token：与访问令牌同密钥、同算法、同身份声明，
// 额外把 aud 指向客户端。客户端可用 JWKS 公钥本地验签获得用户身份。
func (s *Store) IDToken(u User, clientID string) (string, int64, error) {
	if s.Tokens == nil {
		return "", 0, nil
	}
	aud := clientID
	if aud == "" {
		aud = s.Tokens.Audience()
	}
	token, exp, err := s.Tokens.SignForAudience(u, aud)
	if err != nil {
		return "", 0, err
	}
	return token, exp.Unix(), nil
}

func (s *Store) UserFromOAuthToken(ctx context.Context, token string) (*User, error) {
	var u User
	err := s.DB.QueryRowContext(ctx, "SELECT u.id, u.username, COALESCE(u.email,''), u.role FROM auth.oauth_tokens t JOIN auth.users u ON u.id=t.user_id WHERE t.token_hash=$1 AND t.expires_at>now()", sessionHash(token)).Scan(&u.ID, &u.Username, &u.Email, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
