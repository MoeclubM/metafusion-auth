package handler

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// fakeOAuth 是 oauthStore 的内存实现：**判定逻辑全部复用 store 的导出函数**
// （scope 收敛、PKCE、回调白名单、密钥哈希与校验、客户端校验），这里只把"存"换成内存。
// 因此链路用例验的仍然是真实规则，而不是替身自成一套规则。
//
// 需要真实数据库的同一链路回归见 oauth_postgres_test.go（AUTH_TEST_DSN 门控，
// 带上真实 store 与 httptest，跑法写在文件头）。
type fakeOAuth struct {
	tokens *store.TokenIssuer

	mu      sync.Mutex
	clients map[string]store.OAuthClient
	secrets map[string]string // client_id → bcrypt 哈希（空串 = 无密钥第一方）
	owners  map[string]string // client_id → 归属用户 id（空串 = 平台登记，见 developer_fake_test.go）
	users   map[string]store.User
	codes   map[string]fakeCode
	issued  map[string]fakeToken
	audits  []store.OAuthAuditEntry
	seq     int
}

type fakeCode struct {
	clientID    string
	userID      string
	redirectURI string
	scope       string
	challenge   string
	method      string
	used        bool
}

type fakeToken struct {
	clientID string
	userID   string
	scope    string
	revoked  bool
}

func newFakeOAuth(tokens *store.TokenIssuer) *fakeOAuth {
	return &fakeOAuth{
		tokens:  tokens,
		clients: map[string]store.OAuthClient{},
		secrets: map[string]string{},
		owners:  map[string]string{},
		users:   map[string]store.User{},
		codes:   map[string]fakeCode{},
		issued:  map[string]fakeToken{},
	}
}

// addClient 是测试夹具：登记一个客户端（secret 为空表示无密钥第一方）。
func (f *fakeOAuth) addClient(id, name string, uris, scopes []string, trusted bool, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if secret != "" {
		hash, err := store.HashClientSecret(secret)
		if err != nil {
			panic(err)
		}
		f.secrets[id] = hash
	}
	f.clients[id] = store.OAuthClient{
		ID: id, Name: name, RedirectURIs: uris, Scopes: scopes, Trusted: trusted,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func (f *fakeOAuth) addUser(u store.User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.ID] = u
}

func (f *fakeOAuth) next(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

func (f *fakeOAuth) codesFor(match func(fakeCode) bool) int {
	n := 0
	for k, v := range f.codes {
		if v.used || !match(v) {
			continue
		}
		delete(f.codes, k)
		n++
	}
	return n
}

func (f *fakeOAuth) pendingCodeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.codes {
		if !v.used {
			n++
		}
	}
	return n
}

func (f *fakeOAuth) auditActions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.audits))
	for _, e := range f.audits {
		out = append(out, e.Action)
	}
	return out
}

func (f *fakeOAuth) liveTokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.issued {
		if !v.revoked {
			n++
		}
	}
	return n
}

func (f *fakeOAuth) ListOAuthClients(ctx context.Context) ([]store.OAuthClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.OAuthClient{}
	for _, c := range f.clients {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeOAuth) GetOAuthClient(ctx context.Context, id string) (*store.OAuthClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok {
		return nil, sql.ErrNoRows
	}
	c.SecretHash = f.secrets[c.ID]
	return &c, nil
}

func (f *fakeOAuth) CreateOAuthCode(ctx context.Context, clientID, userID, redirectURI, requestedScope, challenge, method string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	client, ok := f.clients[clientID]
	if !ok || client.Disabled {
		return "", "", fmt.Errorf("invalid_client")
	}
	requested, err := store.ParseScopes(requestedScope)
	if err != nil {
		return "", "", err
	}
	granted := store.ConvergeScopes(requested, client.Scopes)
	if len(granted) == 0 {
		return "", "", fmt.Errorf("invalid_scope")
	}
	if !store.RedirectURIAllowed(client.RedirectURIs, redirectURI) {
		return "", "", fmt.Errorf("invalid_redirect_uri")
	}
	challenge = strings.TrimSpace(challenge)
	method = strings.ToUpper(strings.TrimSpace(method))
	if challenge == "" {
		method = ""
	} else if method != "S256" && method != "PLAIN" {
		return "", "", fmt.Errorf("invalid_code_challenge_method")
	}
	code := f.next("code")
	scope := store.FormatScopes(granted)
	f.codes[code] = fakeCode{clientID: clientID, userID: userID, redirectURI: redirectURI, scope: scope, challenge: challenge, method: method}
	return code, scope, nil
}

func (f *fakeOAuth) ExchangeOAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (store.OAuthGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	client, ok := f.clients[clientID]
	if !ok || client.Disabled {
		return store.OAuthGrant{}, fmt.Errorf("invalid_client")
	}
	if hash := f.secrets[clientID]; hash != "" {
		if !store.VerifyClientSecret(hash, clientSecret) {
			return store.OAuthGrant{}, fmt.Errorf("invalid_client_secret")
		}
	} else if !client.Trusted {
		return store.OAuthGrant{}, fmt.Errorf("invalid_client_secret")
	}
	c, ok := f.codes[strings.TrimSpace(code)]
	if !ok || c.clientID != clientID || c.used {
		return store.OAuthGrant{}, fmt.Errorf("expired_or_used_code")
	}
	if redirectURI != "" && redirectURI != c.redirectURI {
		return store.OAuthGrant{}, fmt.Errorf("redirect_uri_mismatch")
	}
	if !store.VerifyPKCE(c.method, c.challenge, verifier) {
		return store.OAuthGrant{}, fmt.Errorf("invalid_code_verifier")
	}
	granted := store.ConvergeScopes(store.SupportedSubset(store.SplitScopes(c.scope)), client.Scopes)
	if len(granted) == 0 {
		return store.OAuthGrant{}, fmt.Errorf("invalid_scope")
	}
	c.used = true
	f.codes[strings.TrimSpace(code)] = c
	user, ok := f.users[c.userID]
	if !ok {
		return store.OAuthGrant{}, fmt.Errorf("invalid_grant")
	}
	// 与生产一致：配置了签发器时访问令牌就是 RS256 JWT（因此同一枚令牌也能被
	// 身份中间件验签），没有签发器才退回不透明随机串。
	token := f.next("at")
	if f.tokens != nil {
		signed, _, _, err := f.tokens.Sign(user)
		if err != nil {
			return store.OAuthGrant{}, err
		}
		token = signed
	}
	scope := store.FormatScopes(granted)
	f.issued[token] = fakeToken{clientID: clientID, userID: c.userID, scope: scope}
	return store.OAuthGrant{Token: token, Scope: scope, ExpiresIn: int(store.AccessTokenTTL.Seconds()), User: &user}, nil
}

func (f *fakeOAuth) OAuthUserinfo(ctx context.Context, token string) (*store.User, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.issued[strings.TrimSpace(token)]
	if !ok || t.revoked {
		return nil, "", fmt.Errorf("invalid_token")
	}
	if c, ok := f.clients[t.clientID]; !ok || c.Disabled {
		return nil, "", fmt.Errorf("invalid_token")
	}
	u, ok := f.users[t.userID]
	if !ok {
		return nil, "", fmt.Errorf("invalid_token")
	}
	return &u, t.scope, nil
}

func (f *fakeOAuth) IDToken(u store.User, clientID string) (string, int64, error) {
	if f.tokens == nil {
		return "", 0, nil
	}
	token, exp, err := f.tokens.SignForAudience(u, clientID)
	if err != nil {
		return "", 0, err
	}
	return token, exp.Unix(), nil
}

func (f *fakeOAuth) RecordOAuthAudit(ctx context.Context, entry store.OAuthAuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, entry)
	return nil
}

func (f *fakeOAuth) ListOAuthAudits(ctx context.Context, clientID string, limit int) ([]store.OAuthAuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.OAuthAuditEntry{}
	for i := len(f.audits) - 1; i >= 0; i-- {
		if clientID != "" && f.audits[i].ClientID != clientID {
			continue
		}
		out = append(out, f.audits[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeOAuth) CreateOAuthClient(ctx context.Context, in store.OAuthClientInput, actor *store.User) (store.OAuthClient, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.Can(actor, "auth.oauth.manage") {
		return store.OAuthClient{}, "", fmt.Errorf("forbidden")
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = "mfc-" + strings.ToLower(strings.ReplaceAll(f.next("id"), "id-", "")) + "0000000"
	}
	if !store.ValidClientID(id) {
		return store.OAuthClient{}, "", fmt.Errorf("invalid_client_id")
	}
	if _, exists := f.clients[id]; exists {
		return store.OAuthClient{}, "", fmt.Errorf("client_exists")
	}
	name := ""
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if name == "" {
		return store.OAuthClient{}, "", fmt.Errorf("invalid_client_name")
	}
	scopes := append([]string{}, store.SupportedScopes...)
	if in.Scopes != nil {
		scopes = *in.Scopes
	}
	if err := store.ValidateClientScopes(scopes); err != nil {
		return store.OAuthClient{}, "", err
	}
	uris := []string{}
	if in.RedirectURIs != nil {
		uris = *in.RedirectURIs
	}
	if err := store.ValidateRedirectURIs(uris); err != nil {
		return store.OAuthClient{}, "", err
	}
	secret, err := store.GenerateClientSecret()
	if err != nil {
		return store.OAuthClient{}, "", err
	}
	hash, err := store.HashClientSecret(secret)
	if err != nil {
		return store.OAuthClient{}, "", err
	}
	client := store.OAuthClient{ID: id, Name: name, RedirectURIs: uris, Scopes: scopes, Trusted: in.Trusted != nil && *in.Trusted, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if in.Disabled != nil {
		client.Disabled = *in.Disabled
	}
	f.clients[id] = client
	f.secrets[id] = hash
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: id, Action: store.OAuthActionClientCreate, Scopes: scopes})
	return client, secret, nil
}

func (f *fakeOAuth) UpdateOAuthClient(ctx context.Context, id string, in store.OAuthClientInput, actor *store.User) (store.OAuthClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.Can(actor, "auth.oauth.manage") {
		return store.OAuthClient{}, fmt.Errorf("forbidden")
	}
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok {
		return store.OAuthClient{}, fmt.Errorf("client_not_found")
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return store.OAuthClient{}, fmt.Errorf("invalid_client_name")
		}
		c.Name = name
	}
	if in.RedirectURIs != nil {
		if err := store.ValidateRedirectURIs(*in.RedirectURIs); err != nil {
			return store.OAuthClient{}, err
		}
		c.RedirectURIs = *in.RedirectURIs
	}
	if in.Scopes != nil {
		if err := store.ValidateClientScopes(*in.Scopes); err != nil {
			return store.OAuthClient{}, err
		}
		c.Scopes = *in.Scopes
	}
	if in.Trusted != nil {
		c.Trusted = *in.Trusted
	}
	if in.Disabled != nil {
		c.Disabled = *in.Disabled
	}
	f.clients[c.ID] = c
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: c.ID, Action: store.OAuthActionClientUpdate})
	return c, nil
}

func (f *fakeOAuth) RotateOAuthClientSecret(ctx context.Context, id string, actor *store.User) (store.OAuthClient, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.Can(actor, "auth.oauth.manage") {
		return store.OAuthClient{}, "", fmt.Errorf("forbidden")
	}
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok {
		return store.OAuthClient{}, "", fmt.Errorf("client_not_found")
	}
	secret, err := store.GenerateClientSecret()
	if err != nil {
		return store.OAuthClient{}, "", err
	}
	hash, err := store.HashClientSecret(secret)
	if err != nil {
		return store.OAuthClient{}, "", err
	}
	f.secrets[c.ID] = hash
	c.SecretHash = hash
	f.clients[c.ID] = c
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: c.ID, Action: store.OAuthActionClientRotate})
	return c, secret, nil
}

func (f *fakeOAuth) DeleteOAuthClient(ctx context.Context, id string, actor *store.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.Can(actor, "auth.oauth.manage") {
		return fmt.Errorf("forbidden")
	}
	id = strings.TrimSpace(id)
	for _, seeded := range []string{"metafusion-catalog", "metafusion-forum", "metafusion-resources"} {
		if seeded == id {
			return fmt.Errorf("seeded_client_immutable")
		}
	}
	if _, ok := f.clients[id]; !ok {
		return fmt.Errorf("client_not_found")
	}
	delete(f.clients, id)
	delete(f.secrets, id)
	for k, v := range f.issued {
		if v.clientID == id {
			delete(f.issued, k)
		}
	}
	f.codesFor(func(c fakeCode) bool { return c.clientID == id })
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: id, Action: store.OAuthActionClientDelete})
	return nil
}

func (f *fakeOAuth) RevokeOAuthTokensByClient(ctx context.Context, clientID string, actor *store.User) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.Can(actor, "auth.oauth.manage") {
		return 0, fmt.Errorf("forbidden")
	}
	clientID = strings.TrimSpace(clientID)
	f.codesFor(func(c fakeCode) bool { return c.clientID == clientID })
	n := 0
	for k, v := range f.issued {
		if v.revoked || v.clientID != clientID {
			continue
		}
		v.revoked = true
		f.issued[k] = v
		n++
	}
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: clientID, Action: store.OAuthActionTokensRevoked})
	return n, nil
}

func (f *fakeOAuth) RevokeOAuthTokensByUser(ctx context.Context, userID string, actor *store.User) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.Can(actor, "auth.oauth.manage") {
		return 0, fmt.Errorf("forbidden")
	}
	userID = strings.TrimSpace(userID)
	f.codesFor(func(c fakeCode) bool { return c.userID == userID })
	n := 0
	for k, v := range f.issued {
		if v.revoked || v.userID != userID {
			continue
		}
		v.revoked = true
		f.issued[k] = v
		n++
	}
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: "", Action: store.OAuthActionTokensRevoked, Detail: "user:" + userID})
	return n, nil
}
