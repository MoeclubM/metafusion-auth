package handler

// fakeOAuth 的开发者中心实现（developerStore）。
//
// 与真实实现的边界：归属判定与投影都调 store 的导出函数（CanEditApp / DeveloperAppOf /
// Validate*），也就是说"谁能改、自有平台怎么认、拿不到密钥时怎么显示"这些规则只此一份；
// 内存里只多存一件真实实现放在数据库列里的事——归属（owners）。
//
// 这里不做数据库唯一约束、并发与审计落库那些只有真库才有的行为，它们由
// TestDeveloperCenterAgainstPostgres 与 store 包的真库用例覆盖。

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

func (f *fakeOAuth) ownedCount(userID string) int {
	n := 0
	for _, owner := range f.owners {
		if owner == userID {
			n++
		}
	}
	return n
}

func (f *fakeOAuth) listApps(actor *store.User) []store.DeveloperApp {
	out := []store.DeveloperApp{}
	for id, c := range f.clients {
		c.ID = id
		c.OwnerID = f.owners[id]
		c.SecretHash = f.secrets[id]
		if !store.CanEditApp(actor, c.OwnerID) {
			continue
		}
		out = append(out, store.DeveloperAppOf(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (f *fakeOAuth) ListDeveloperApps(ctx context.Context, actor *store.User) ([]store.DeveloperApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listApps(actor), nil
}

// ListPlatformApps 只回"免同意且没有归属"的客户端：与真实实现的 SQL 条件逐字对应。
func (f *fakeOAuth) ListPlatformApps(ctx context.Context) ([]store.DeveloperApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []store.DeveloperApp{}
	for id, c := range f.clients {
		if !c.Trusted || f.owners[id] != "" {
			continue
		}
		c.ID = id
		c.SecretHash = f.secrets[id]
		out = append(out, store.DeveloperAppOf(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeOAuth) GetDeveloperApp(ctx context.Context, id string, actor *store.User) (*store.DeveloperApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok || !store.CanEditApp(actor, f.owners[c.ID]) {
		return nil, fmt.Errorf("client_not_found")
	}
	c.OwnerID = f.owners[c.ID]
	c.SecretHash = f.secrets[c.ID]
	app := store.DeveloperAppOf(c)
	return &app, nil
}

func (f *fakeOAuth) CreateDeveloperApp(ctx context.Context, in store.DeveloperAppInput, actor *store.User) (store.DeveloperApp, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if actor == nil {
		return store.DeveloperApp{}, "", fmt.Errorf("authentication_required")
	}
	// 配额：管理员不受限，与真实实现同一条判定。
	if !store.Can(actor, "auth.oauth.manage") && f.ownedCount(actor.ID) >= store.MaxDeveloperAppsPerUser {
		return store.DeveloperApp{}, "", fmt.Errorf("app_quota_exceeded")
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = "mfc-dev-" + strings.ToLower(strings.ReplaceAll(f.next("id"), "id-", "")) + "000"
	}
	if !store.ValidClientID(id) {
		return store.DeveloperApp{}, "", fmt.Errorf("invalid_client_id")
	}
	if _, exists := f.clients[id]; exists {
		return store.DeveloperApp{}, "", fmt.Errorf("client_exists")
	}
	name := ""
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if name == "" {
		return store.DeveloperApp{}, "", fmt.Errorf("invalid_client_name")
	}
	description, homepage := "", ""
	if in.Description != nil {
		description = strings.TrimSpace(*in.Description)
	}
	if err := store.ValidateClientDescription(description); err != nil {
		return store.DeveloperApp{}, "", err
	}
	if in.HomepageURL != nil {
		homepage = strings.TrimSpace(*in.HomepageURL)
	}
	if err := store.ValidateHomepageURL(homepage); err != nil {
		return store.DeveloperApp{}, "", err
	}
	scopes := append([]string{}, store.SupportedScopes...)
	if in.Scopes != nil {
		scopes = *in.Scopes
	}
	if err := store.ValidateClientScopes(scopes); err != nil {
		return store.DeveloperApp{}, "", err
	}
	uris := []string{}
	if in.RedirectURIs != nil {
		uris = *in.RedirectURIs
	}
	if err := store.ValidateRedirectURIs(uris); err != nil {
		return store.DeveloperApp{}, "", err
	}
	secret, err := store.GenerateClientSecret()
	if err != nil {
		return store.DeveloperApp{}, "", err
	}
	hash, err := store.HashClientSecret(secret)
	if err != nil {
		return store.DeveloperApp{}, "", err
	}
	client := store.OAuthClient{ID: id, Name: name, Description: description, HomepageURL: homepage, RedirectURIs: uris, Scopes: scopes, OwnerID: actor.ID, CreatedAt: "2026-01-01T00:00:00Z"}
	f.clients[id] = client
	f.secrets[id] = hash
	f.owners[id] = actor.ID
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: id, Action: store.OAuthActionClientCreate, Scopes: scopes})
	client.SecretHash = hash
	return store.DeveloperAppOf(client), secret, nil
}

func (f *fakeOAuth) UpdateDeveloperApp(ctx context.Context, id string, in store.DeveloperAppInput, actor *store.User) (store.DeveloperApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok || !store.CanEditApp(actor, f.owners[c.ID]) {
		return store.DeveloperApp{}, fmt.Errorf("client_not_found")
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return store.DeveloperApp{}, fmt.Errorf("invalid_client_name")
		}
		c.Name = name
	}
	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if err := store.ValidateClientDescription(description); err != nil {
			return store.DeveloperApp{}, err
		}
		c.Description = description
	}
	if in.HomepageURL != nil {
		homepage := strings.TrimSpace(*in.HomepageURL)
		if err := store.ValidateHomepageURL(homepage); err != nil {
			return store.DeveloperApp{}, err
		}
		c.HomepageURL = homepage
	}
	if in.RedirectURIs != nil {
		if err := store.ValidateRedirectURIs(*in.RedirectURIs); err != nil {
			return store.DeveloperApp{}, err
		}
		c.RedirectURIs = *in.RedirectURIs
	}
	if in.Scopes != nil {
		if err := store.ValidateClientScopes(*in.Scopes); err != nil {
			return store.DeveloperApp{}, err
		}
		c.Scopes = *in.Scopes
	}
	f.clients[c.ID] = c
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: c.ID, Action: store.OAuthActionClientUpdate})
	c.SecretHash = f.secrets[c.ID]
	return store.DeveloperAppOf(c), nil
}

func (f *fakeOAuth) RotateDeveloperAppSecret(ctx context.Context, id string, actor *store.User) (store.DeveloperApp, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok || !store.CanEditApp(actor, f.owners[c.ID]) {
		return store.DeveloperApp{}, "", fmt.Errorf("client_not_found")
	}
	secret, err := store.GenerateClientSecret()
	if err != nil {
		return store.DeveloperApp{}, "", err
	}
	hash, err := store.HashClientSecret(secret)
	if err != nil {
		return store.DeveloperApp{}, "", err
	}
	f.secrets[c.ID] = hash
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: c.ID, Action: store.OAuthActionClientRotate})
	c.SecretHash = hash
	return store.DeveloperAppOf(c), secret, nil
}

func (f *fakeOAuth) DeleteDeveloperApp(ctx context.Context, id string, actor *store.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[strings.TrimSpace(id)]
	if !ok || !store.CanEditApp(actor, f.owners[c.ID]) {
		return fmt.Errorf("client_not_found")
	}
	delete(f.clients, c.ID)
	delete(f.secrets, c.ID)
	delete(f.owners, c.ID)
	f.audits = append(f.audits, store.OAuthAuditEntry{ActorID: actor.ID, ClientID: c.ID, Action: store.OAuthActionClientDelete})
	return nil
}

// markVerified 是测试夹具：把某个客户端标成"已核验"（真实实现里这一步由管理员在管理台做，
// 走 PUT /api/admin/oauth/clients/{id} 的 verified 字段）。
func (f *fakeOAuth) markVerified(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[id]
	if !ok {
		return
	}
	c.Verified = true
	f.clients[id] = c
}
