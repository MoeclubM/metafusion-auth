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

// ── scope ──

// SupportedScopes 是账号服务承认的 scope 集合：发现文档的 scopes_supported、同意页的
// 说明文案与"请求收敛"都以它为准。新增一项必须同时补 handler/consent.go 的四语说明，
// 否则同意页会漏展示（由 handler 用例拦）。
var SupportedScopes = []string{"openid", "profile", "email"}

// DefaultScope 是请求未带 scope 时的默认值：与拆分前的默认值逐字一致，
// 老客户端（不传 scope）仍拿到同一个 scope。
const DefaultScope = "profile"

// ValidScope 判定单个 scope 是否受支持。
func ValidScope(code string) bool {
	code = strings.TrimSpace(code)
	for _, s := range SupportedScopes {
		if s == code {
			return true
		}
	}
	return false
}

// SplitScopes 把空格分隔的 scope 串拆成去重保序的集合，不做支持性判断。
func SplitScopes(raw string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, code := range strings.Fields(raw) {
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

// UnsupportedScopes 返回请求里不受支持的 scope：错误响应靠它点明是哪一项，
// 而不是只回一个笼统的 invalid_scope。
func UnsupportedScopes(raw string) []string {
	out := []string{}
	for _, code := range SplitScopes(raw) {
		if !ValidScope(code) {
			out = append(out, code)
		}
	}
	return out
}

// SupportedSubset 过滤掉不受支持的 scope。只用于处理**存量数据**（已经发出的授权码）：
// 新请求一律走 ParseScopes 直接报错，不把不支持的 scope 静默降级。
func SupportedSubset(codes []string) []string {
	out := []string{}
	for _, code := range codes {
		if ValidScope(code) {
			out = append(out, code)
		}
	}
	return out
}

// ParseScopes 校验并归一化请求 scope：出现不支持的项直接 invalid_scope（不静默丢弃），
// 整个参数为空时回落 DefaultScope。
func ParseScopes(raw string) ([]string, error) {
	if len(UnsupportedScopes(raw)) > 0 {
		return nil, fmt.Errorf("invalid_scope")
	}
	codes := SplitScopes(raw)
	if len(codes) == 0 {
		return []string{DefaultScope}, nil
	}
	return codes, nil
}

// ConvergeScopes 收敛为「客户端允许 ∩ 请求」：保持请求顺序；客户端没被允许的一律不给，
// 因此给第三方的永远只是白名单的子集。
func ConvergeScopes(requested, allowed []string) []string {
	allow := map[string]bool{}
	for _, code := range allowed {
		allow[strings.TrimSpace(code)] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, code := range requested {
		code = strings.TrimSpace(code)
		if !allow[code] || seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out
}

// FormatScopes 是 scope 的存储与传输形式：空格分隔（与 OAuth 的 scope 参数一致）。
func FormatScopes(scopes []string) string { return strings.Join(scopes, " ") }

// ValidateClientScopes 校验管理 API 登记的客户端 scope 白名单：非空且全部受支持。
func ValidateClientScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("invalid_scopes")
	}
	for _, code := range scopes {
		if !ValidScope(code) {
			return fmt.Errorf("invalid_scope: %s", code)
		}
	}
	return nil
}

// RedirectURIAllowed 用逐字相等比较回调地址：白名单就是完整地址，
// 不做前缀/通配匹配（通配会让任何子域或路径都能收码）。
func RedirectURIAllowed(allowed []string, redirectURI string) bool {
	for _, uri := range allowed {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

type OAuthClient struct {
	ID           string   `json:"client_id"`
	SecretHash   string   `json:"-"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Trusted      bool     `json:"trusted"`
	CreatedAt    string   `json:"created_at"`
}

func (s *Store) ListOAuthClients(ctx context.Context) ([]OAuthClient, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT id, name, redirect_uris, scopes, trusted, created_at FROM auth.oauth_clients ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []OAuthClient
	for rows.Next() {
		var c OAuthClient
		var uris, scopes []string
		var t time.Time
		if err := rows.Scan(&c.ID, &c.Name, pq.Array(&uris), pq.Array(&scopes), &c.Trusted, &t); err != nil {
			return nil, err
		}
		c.RedirectURIs = uris
		c.Scopes = scopes
		c.CreatedAt = t.UTC().Format(time.RFC3339)
		list = append(list, c)
	}
	return list, rows.Err()
}

func (s *Store) GetOAuthClient(ctx context.Context, id string) (*OAuthClient, error) {
	var c OAuthClient
	var uris, scopes []string
	var t time.Time
	err := s.DB.QueryRowContext(ctx, "SELECT id, secret_hash, name, redirect_uris, scopes, trusted, created_at FROM auth.oauth_clients WHERE id=$1", strings.TrimSpace(id)).Scan(&c.ID, &c.SecretHash, &c.Name, pq.Array(&uris), pq.Array(&scopes), &c.Trusted, &t)
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = uris
	c.Scopes = scopes
	c.CreatedAt = t.UTC().Format(time.RFC3339)
	return &c, nil
}

// CreateOAuthCode 签发授权码：challenge 为 PKCE code_challenge（可空），method 仅接受
// S256/plain，其它值拒绝（避免降级绕过）。
//
// scope 在这里**再收敛一次**（调用方通常已按收敛结果渲染过同意页）：写进码里的只能是
// 「客户端允许 ∩ 请求」的交集，任何调用方都无法把客户端没被允许的 scope 塞进码里。
// 返回码与最终写库的 scope。
func (s *Store) CreateOAuthCode(ctx context.Context, clientID string, userID string, redirectURI, requestedScope, challenge, method string) (string, string, error) {
	client, err := s.GetOAuthClient(ctx, clientID)
	if err != nil || client == nil {
		return "", "", fmt.Errorf("invalid_client")
	}
	requested, err := ParseScopes(requestedScope)
	if err != nil {
		return "", "", err
	}
	granted := ConvergeScopes(requested, client.Scopes)
	if len(granted) == 0 {
		return "", "", fmt.Errorf("invalid_scope")
	}
	if !RedirectURIAllowed(client.RedirectURIs, redirectURI) {
		return "", "", fmt.Errorf("invalid_redirect_uri")
	}
	challenge = strings.TrimSpace(challenge)
	method = strings.ToUpper(strings.TrimSpace(method))
	if challenge == "" {
		method = ""
	} else if method != "S256" && method != "PLAIN" {
		return "", "", fmt.Errorf("invalid_code_challenge_method")
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	code := hex.EncodeToString(b)
	scope := FormatScopes(granted)
	if _, err := s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_codes(code, client_id, user_id, redirect_uri, scope, expires_at, code_challenge, code_challenge_method) VALUES($1, $2, $3, $4, $5, $6, $7, $8)", code, clientID, userID, redirectURI, scope, time.Now().Add(10*time.Minute), challenge, method); err != nil {
		return "", "", err
	}
	return code, scope, nil
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

// OAuthGrant 是一次成功的授权码兑换：令牌、最终 scope 与**真实**有效期。
// ExpiresIn 直接取自签发器（JWT 为 AccessTokenTTL），响应里的 expires_in 不再估算。
type OAuthGrant struct {
	Token     string
	Scope     string
	ExpiresIn int
	User      *User
}

func (s *Store) ExchangeOAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (OAuthGrant, error) {
	client, err := s.GetOAuthClient(ctx, clientID)
	if err != nil || client == nil {
		return OAuthGrant{}, fmt.Errorf("invalid_client")
	}
	if client.SecretHash != "" {
		if clientSecret == "" || bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)) != nil {
			return OAuthGrant{}, fmt.Errorf("invalid_client_secret")
		}
	} else if !client.Trusted {
		// 无密钥的非受信客户端一律拒绝：空密钥只能是预置受信第一方，
		// 且第一方也应尽快配置密钥或改走 PKCE。
		return OAuthGrant{}, fmt.Errorf("invalid_client_secret")
	}
	var userID string
	var codeURI string
	var codeScope string
	var challenge, challengeMethod string
	// 先读码并完成全部校验，再原子标记已用：PKCE/redirect 校验失败**不得消耗**
	// 授权码，否则一次错误 verifier 请求即可作废合法客户端刚拿到的码。
	// 单次性由下方条件 UPDATE 保证：并发双兑只有一个成功，后到者按未命中
	// 拿到 expired_or_used_code。
	err = s.DB.QueryRowContext(ctx, "SELECT user_id, redirect_uri, scope, COALESCE(code_challenge,''), COALESCE(code_challenge_method,'') FROM auth.oauth_codes WHERE code=$1 AND client_id=$2 AND used=false AND expires_at>now()", strings.TrimSpace(code), clientID).Scan(&userID, &codeURI, &codeScope, &challenge, &challengeMethod)
	if err != nil {
		return OAuthGrant{}, fmt.Errorf("expired_or_used_code")
	}
	if redirectURI != "" && redirectURI != codeURI {
		return OAuthGrant{}, fmt.Errorf("redirect_uri_mismatch")
	}
	if !verifyPKCE(challengeMethod, challenge, verifier) {
		return OAuthGrant{}, fmt.Errorf("invalid_code_verifier")
	}
	res, err := s.DB.ExecContext(ctx, "UPDATE auth.oauth_codes SET used=true WHERE code=$1 AND client_id=$2 AND used=false AND expires_at>now()", strings.TrimSpace(code), clientID)
	if err != nil {
		return OAuthGrant{}, fmt.Errorf("invalid_grant")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return OAuthGrant{}, fmt.Errorf("expired_or_used_code")
	}
	// 换码时按客户端**当前**的 scope 白名单再收敛一次：管理员可能在发码之后收紧了白名单，
	// 令牌只能更少、不能更多。存量码里若有已不再支持的 scope 按支持集合过滤掉，
	// 不静默放宽成默认 scope。
	granted := ConvergeScopes(SupportedSubset(SplitScopes(codeScope)), client.Scopes)
	if len(granted) == 0 {
		return OAuthGrant{}, fmt.Errorf("invalid_scope")
	}
	var u User
	if err = s.DB.QueryRowContext(ctx, "SELECT id, username, COALESCE(email,''), role FROM auth.users WHERE id=$1", userID).Scan(&u.ID, &u.Username, &u.Email, &u.Role); err != nil {
		return OAuthGrant{}, err
	}
	// 签发 OIDC access_token：配置签发器时为 RS256 JWT（可被 JWKS 本地验签），
	// 否则退回不透明随机串。无论哪种都只落 SHA-256 以便吊销。
	token, ttl, exp, err := s.signOAuthToken(u)
	if err != nil {
		return OAuthGrant{}, err
	}
	// 行的过期时刻与令牌真实有效期一致：JWT 只有 AccessTokenTTL，行留 30 天会让
	// "查库兜底"把已过期的令牌当成有效（userinfo 以存活行为准，见 C4）。
	expiresAt := time.Now().Add(ttl)
	if exp > 0 {
		expiresAt = time.Unix(exp, 0)
	}
	scope := FormatScopes(granted)
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO auth.oauth_tokens(token_hash, client_id, user_id, scope, expires_at) VALUES($1, $2, $3, $4, $5)", sessionHash(token), clientID, userID, scope, expiresAt); err != nil {
		return OAuthGrant{}, err
	}
	return OAuthGrant{Token: token, Scope: scope, ExpiresIn: int(ttl.Seconds()), User: &u}, nil
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
	// 用常量而不是 time.Until(exp)：后者带签发耗时误差，会让 expires_in 报出 899 这种数字。
	return token, AccessTokenTTL, exp.Unix(), nil
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
