package store

// 账号令牌：RS256（RSASSA-PKCS1-v1_5 + SHA-256）自包含 JWT。
//
// 用标准库实现而非引入第三方 JWT 依赖：部署环境对模块代理访问受限，且
// RS256 的签名/验签只是 crypto/rsa 的 SignPKCS1v15/VerifyPKCS1v15 加一段
// base64url，几行即可，少一层供应链风险。
//
// 验签只需要公钥，因此鉴权中间件可以完全本地判定（不查库）；服务端会话仍
// 保留，作为双模式兜底与可吊销来源，存量随机会话令牌不受影响。

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// AccessTokenTTL 是无状态访问令牌的有效期。取得短一些，让登出/改密这类
// 需要快速失效的场景影响面有限；续期由服务端会话（及 /auth/refresh）承担。
const AccessTokenTTL = 15 * time.Minute

// Claims 是访问令牌的载荷。字段名遵循 OIDC 惯例，便于 E3 直接复用为 id_token。
type Claims struct {
	Subject     string   `json:"sub"`
	Username    string   `json:"preferred_username"`
	Email       string   `json:"email,omitempty"`
	Role        string   `json:"role"`
	Groups      []string `json:"groups,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Issuer      string   `json:"iss"`
	Audience    string   `json:"aud"`
	IssuedAt    int64    `json:"iat"`
	Expires     int64    `json:"exp"`
	JTI         string   `json:"jti"`
	// TokenUse 区分令牌用途（S01）：session=站内会话（完整权限），oauth=第三方
	// OAuth 访问令牌（仅身份、无管理能力），id_token=OIDC 断言（仅发给当事客户端）。
	// 缺省（空串）按历史会话语义处理，保证存量令牌可验；下游管理 API 只接受
	// session/缺省，oauth/id_token 一律拒绝（见 Can 与各服务的验签契约）。
	TokenUse string `json:"token_use,omitempty"`
	// ClientID/Scope 只在 oauth/id_token 上出现：令牌被绑定到哪次授权，
	// 下游据此做身份展示的 scope 裁剪，而不是据此放行管理能力。
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

// 令牌用途取值。与 User.TokenUse 同源（见 store.go），判定只认这三个值与空串。
const (
	TokenUseSession = "session"
	TokenUseOAuth   = "oauth"
	TokenUseIDToken = "id_token"
)

// validTokenUse 判定载荷里的用途声明是否合法：未知取值直接拒收，
// 防止将来新增用途的令牌被当成已知用途放行。
func validTokenUse(use string) bool {
	switch use {
	case "", TokenUseSession, TokenUseOAuth, TokenUseIDToken:
		return true
	default:
		return false
	}
}

// TokenIssuer 持有签名私钥与验签公钥。零值不可用，需经 NewTokenIssuerFromEnv。
type TokenIssuer struct {
	mu        sync.RWMutex
	priv      *rsa.PrivateKey
	kid       string
	issuer    string
	audience  string
	ephemeral bool
	// now 可在测试中替换，用于验证过期与注销过期逻辑；nil 表示 time.Now。
	now func() time.Time
	// revoked 记录已注销的 jti 及其过期时刻。单实例内存实现；多实例部署时应
	// 换成 Redis 集合，否则注销无法跨实例生效。条目随过期时间被惰性清理。
	revoked map[string]int64
	// audiences 是本签发器认可的受众集合：默认受众之外，OIDC id_token 以
	// client_id 为受众（SignForAudience 签发时登记）。验签按集合判断，
	// 未登记的受众一律拒绝，防止令牌在 relying party 之间混淆。
	audiences map[string]bool
}

func (t *TokenIssuer) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// NewTokenIssuerFromEnv 从 AUTH_JWT_PRIVATE_KEY 读取 RSA 私钥（PEM 文本，或
// 其 base64 编码），支持 PKCS#1 与 PKCS#8。
//
// 未配置私钥时**默认拒绝启动**：进程内临时密钥意味着每次重启都换掉签发密钥——已签发令牌
// 静默失效、JWKS 发布出去的是没人固定过的公钥、密钥轮换无人知晓，而这一切原先只留一行日志
// （2026-09-19 审计 S-9）。只有显式打开本地开发开关 AUTH_JWT_ALLOW_EPHEMERAL_KEY 才回退到
// 临时密钥，调用方（cmd/server）会为此打一条 WARNING。
func NewTokenIssuerFromEnv(issuer, audience string) (*TokenIssuer, error) {
	t := &TokenIssuer{issuer: issuer, audience: audience, revoked: map[string]int64{}, audiences: map[string]bool{}}
	if audience != "" {
		t.audiences[audience] = true
	}
	raw := strings.TrimSpace(os.Getenv("AUTH_JWT_PRIVATE_KEY"))
	if raw == "" {
		if !ephemeralKeyAllowed() {
			return nil, errors.New("AUTH_JWT_PRIVATE_KEY is required: refusing to start with an in-process key " +
				"(tokens would silently expire on every restart; for local development only, set AUTH_JWT_ALLOW_EPHEMERAL_KEY=1)")
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		t.priv, t.kid, t.ephemeral = key, keyID(&key.PublicKey), true
		return t, nil
	}
	if !strings.Contains(raw, "-----BEGIN") {
		if dec, err := base64.StdEncoding.DecodeString(raw); err == nil {
			raw = string(dec)
		}
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("AUTH_JWT_PRIVATE_KEY is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		t.priv, t.kid = k, keyID(&k.PublicKey)
		return t, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("AUTH_JWT_PRIVATE_KEY must be PKCS#1 or PKCS#8 RSA: %w", err)
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("AUTH_JWT_PRIVATE_KEY must be an RSA key")
	}
	t.priv, t.kid = k, keyID(&k.PublicKey)
	return t, nil
}

// ephemeralKeyAllowed 是显式的本地开发开关：只认明确的真值，空值、拼错或任何其它取值都按
// "不允许"处理（fail closed——开关写错不能把生产悄悄变回静默降级）。
func ephemeralKeyAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_JWT_ALLOW_EPHEMERAL_KEY"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Ephemeral 表示当前使用进程内临时密钥：只在显式打开 AUTH_JWT_ALLOW_EPHEMERAL_KEY 时可能为真
// （见 NewTokenIssuerFromEnv），调用方据此打告警。
func (t *TokenIssuer) Ephemeral() bool { return t != nil && t.ephemeral }

func (t *TokenIssuer) Issuer() string   { return t.issuer }
func (t *TokenIssuer) Audience() string { return t.audience }
func (t *TokenIssuer) KeyID() string    { return t.kid }

// TokenIssuerURL 返回 OIDC issuer 基址（也是 discovery/JWKS 的挂载根）。
// Store 上暴露给 HTTP 层，避免在 http.go 里直接读环境变量。
func (s *Store) TokenIssuerURL() string {
	if s.Tokens == nil {
		return ""
	}
	return s.Tokens.Issuer()
}

// Sign 签发站内会话访问令牌，返回 token 与其 jti（jti 用于注销与审计关联）。
// 会话令牌携带完整身份与权限（role/groups/permissions/email），供站内管理 API 使用。
func (t *TokenIssuer) Sign(u User) (string, string, time.Time, error) {
	u.TokenUse = TokenUseSession
	u.ClientID, u.Scope = "", ""
	return t.sign(u, t.audience)
}

// SignOAuth 签发第三方 OAuth 访问令牌（S01）：audience 仍是平台受众（JWKS/issuer
// 配置不动），但载荷只剩 scope 裁剪后的身份——role 恒为 user、组与权限恒空、
// email 仅在授予 email scope 时出现。未打补丁的下游即使只验 aud，也会因
// role/permissions 为空而拒绝管理能力；已打补丁的下游再按 token_use=oauth
// 在管理 API 上默认拒绝（见 README「令牌用途隔离」）。
func (t *TokenIssuer) SignOAuth(u User, clientID string, scopes []string) (string, string, time.Time, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", "", time.Time{}, errors.New("empty client_id")
	}
	ru := OAuthTokenUser(u, scopes)
	ru.TokenUse = TokenUseOAuth
	ru.ClientID = strings.TrimSpace(clientID)
	ru.Scope = FormatScopes(scopes)
	return t.sign(ru, t.audience)
}

// SignForAudience 以指定 aud 签发令牌，用于 OIDC id_token（aud 指向客户端）。
// 签发即登记该受众：Verify 只接受已登记受众，未登记的 aud 一律拒绝。
// id_token 只发给当事客户端（aud=client_id，平台受众的验签方天然拒收），
// 用途标记为 id_token，同样不得用于站内管理 API。
func (t *TokenIssuer) SignForAudience(u User, audience string) (string, time.Time, error) {
	if audience == "" {
		return "", time.Time{}, errors.New("empty audience")
	}
	t.mu.Lock()
	t.audiences[audience] = true
	t.mu.Unlock()
	u.TokenUse = TokenUseIDToken
	u.ClientID, u.Scope = "", ""
	token, _, exp, err := t.sign(u, audience)
	return token, exp, err
}

func (t *TokenIssuer) sign(u User, audience string) (string, string, time.Time, error) {
	if t == nil || t.priv == nil {
		return "", "", time.Time{}, errors.New("token issuer unavailable")
	}
	now := t.clock()
	exp := now.Add(AccessTokenTTL)
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", "", time.Time{}, err
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)
	claims := Claims{
		Subject: u.ID, Username: u.Username, Email: u.Email, Role: u.Role,
		Groups: u.Groups, Permissions: u.Permissions,
		Issuer: t.issuer, Audience: audience,
		IssuedAt: now.Unix(), Expires: exp.Unix(), JTI: jti,
		TokenUse: u.TokenUse, ClientID: u.ClientID, Scope: u.Scope,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", "", time.Time{}, err
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": t.kid})
	if err != nil {
		return "", "", time.Time{}, err
	}
	signing := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, t.priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", "", time.Time{}, err
	}
	return signing + "." + b64(sig), jti, exp, nil
}

// Verify 校验签名与时间窗，并检查是否已被注销。任何一步失败都返回错误，
// 调用方据此回退到服务端会话查库（双模式）。
func (t *TokenIssuer) Verify(token string) (*Claims, error) {
	if t == nil || t.priv == nil {
		return nil, errors.New("token issuer unavailable")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, errors.New("malformed header")
	}
	// 只接受 RS256：拒绝 none/HS* 等算法，避免算法混淆攻击。
	if header.Alg != "RS256" {
		return nil, errors.New("unexpected algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&t.priv.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("bad signature")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	var claims Claims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, errors.New("malformed payload")
	}
	// 未知用途的令牌一律拒收：不能把将来新增用途的令牌当成已知用途放行。
	if !validTokenUse(claims.TokenUse) {
		return nil, errors.New("bad token_use")
	}
	now := t.clock().Unix()
	if claims.Expires == 0 || now >= claims.Expires {
		return nil, errors.New("token expired")
	}
	if claims.Issuer != t.issuer {
		return nil, errors.New("bad issuer")
	}
	// 受众按登记集合判断：默认受众之外，SignForAudience 签发的 id_token 受众
	// （client_id）在签发时登记。未登记受众拒绝，防止令牌跨 relying party 混用。
	t.mu.RLock()
	audOK := t.audiences[claims.Audience]
	t.mu.RUnlock()
	if !audOK {
		return nil, errors.New("bad audience")
	}
	if claims.Subject == "" {
		return nil, errors.New("missing subject")
	}
	t.mu.Lock()
	if exp, bad := t.revoked[claims.JTI]; bad && now < exp {
		t.mu.Unlock()
		return nil, errors.New("token revoked")
	}
	// 惰性清理：顺带清掉已过期的注销记录，避免 map 无限增长。
	for k, exp := range t.revoked {
		if now >= exp {
			delete(t.revoked, k)
		}
	}
	t.mu.Unlock()
	return &claims, nil
}

// Revoke 把 jti 加入注销集合直到其自然过期。单实例内存实现。
func (t *TokenIssuer) Revoke(jti string, expires int64) {
	if t == nil || jti == "" {
		return
	}
	t.mu.Lock()
	t.revoked[jti] = expires
	t.mu.Unlock()
}

// RevokeToken 校验后注销单个令牌（登出路径用；验签失败则无需注销）。
func (t *TokenIssuer) RevokeToken(token string) {
	c, err := t.Verify(token)
	if err != nil {
		return
	}
	t.Revoke(c.JTI, c.Expires)
}

// PublicJWK 返回验签公钥的 JWK 表示，供 /oidc JWKS 端点与外部服务本地验签。
func (t *TokenIssuer) PublicJWK() map[string]any {
	if t == nil || t.priv == nil {
		return nil
	}
	pub := t.priv.PublicKey
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": t.kid,
		"n":   b64(pub.N.Bytes()),
		"e":   b64(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ClaimsToUser 把已验签的载荷还原为 User（只含身份与角色，不查库）。
func ClaimsToUser(c *Claims) *User {
	if c == nil {
		return nil
	}
	// 组与权限随令牌下发：下游服务本地验签即可判定能力；权限变更最迟在令牌续期时生效。
	// 用途与授权绑定一并透传：管理闸门（Can/requirePermission）据此拒绝第三方令牌，
	// 而不是只看 role/permissions 是否为空（显式空权限不得回落，见 access.go）。
	u := &User{ID: c.Subject, Username: c.Username, Email: c.Email, Role: c.Role, Groups: c.Groups, Permissions: c.Permissions,
		TokenUse: c.TokenUse, ClientID: c.ClientID, Scope: c.Scope}
	// 进程内把第三方身份的空权限显式化：JSON 反序列化后 nil 与 [] 都是 len 0，
	// 这里统一成空切片，表明"已声明无权限"，而不是"没有权限声明"。
	if (u.TokenUse == TokenUseOAuth || u.TokenUse == TokenUseIDToken) && u.Permissions == nil {
		u.Permissions = []string{}
	}
	return u
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// keyID 取公钥 SPKI DER 的 SHA-256 前 8 字节，作为稳定且不泄露密钥的 kid。
func keyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "default"
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}
