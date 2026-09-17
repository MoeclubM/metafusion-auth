package store

// 开发者中心（Developer Center）的存储侧：应用自助登记与自有平台清单。
//
// 与 oauth.go 的分工：oauth.go 管"授权方怎么工作"（授权码、令牌、同意、吊销与审计），
// 本文件管"谁能登记、谁能改"——管理台按权限码（auth.oauth.manage），开发者中心按归属
// （oauth_clients.owner_user_id）。两条路径共用 oauth.go 的同一份校验与写入实现，
// 差别只在传进去的那一个判定函数。
//
// 开发者面**只服务自有应用**：列表与读 / 改 / 轮换 / 删一律只认"归属 = 当前账号"，不看角色。
// 管理员要看、要改全部客户端，走的是管理面 /api/admin/oauth/clients*（全量治理 + 权限码），
// 开发者面没有再给第二份的理由：管理员在这里看到系统应用与别人的应用，等于把管理面能力
// 泄漏到自助面（那里连种子客户端的删除保护都没有，轮换更是无保护）。
//
// 刻意保留的边界：开发者中心**写不了管理面字段**（trusted / disabled / verified），
// 也不能把自己登记的应用变成"自有平台"。免同意是平台自己的身份，不能由请求方声明；
// 核验同理，只在管理面做（PUT /api/admin/oauth/clients/{id} 带 verified）。

import (
	"context"
	"fmt"
)

// MaxDeveloperAppsPerUser 是单个账号在开发者中心可登记的应用数上限。自助入口必须有上限：
// 否则任何登录用户都能刷出无限多个 client_id，把客户端命名空间与审计表撑满。
const MaxDeveloperAppsPerUser = 20

// DeveloperApp 是开发者中心的应用投影：在 OAuthClient 之上补齐"归属、自有平台、核验"三种解读。
//
// FirstParty 与 Verified 的区别：前者是"这个应用属于平台自己"（免同意），后者是"已被核验"
// （同意页据此决定要不要显示未核验提示）。自有平台恒为已核验——免同意本身就是最强的核验表达。
type DeveloperApp struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	HomepageURL  string   `json:"homepage_url"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	FirstParty   bool     `json:"first_party"`
	Verified     bool     `json:"verified"`
	Disabled     bool     `json:"disabled"`
	HasSecret    bool     `json:"has_secret"`
	OwnerID      string   `json:"owner_user_id,omitempty"`
	Owner        string   `json:"owner_username,omitempty"`
	CreatedAt    string   `json:"created_at"`
}

// DeveloperAppInput 是开发者中心可写的字段（全可选 = 部分更新）。
// 管理面字段刻意不在这个结构里：它们在这条路径上不是"没传就不改"，而是根本不允许出现。
type DeveloperAppInput struct {
	ID           string    `json:"client_id"`
	Name         *string   `json:"name"`
	Description  *string   `json:"description"`
	HomepageURL  *string   `json:"homepage_url"`
	RedirectURIs *[]string `json:"redirect_uris"`
	Scopes       *[]string `json:"scopes"`
}

// ToClientInput 转成共用写入形状（开发者路径永不携带管理面字段）。
func (in DeveloperAppInput) ToClientInput() OAuthClientInput {
	return OAuthClientInput{
		ID: in.ID, Name: in.Name, Description: in.Description,
		HomepageURL: in.HomepageURL, RedirectURIs: in.RedirectURIs, Scopes: in.Scopes,
	}
}

func DeveloperAppOf(c OAuthClient) DeveloperApp {
	return DeveloperApp{
		ID: c.ID, Name: c.Name, Description: c.Description, HomepageURL: c.HomepageURL,
		RedirectURIs: c.RedirectURIs, Scopes: c.Scopes,
		FirstParty: c.FirstParty(), Verified: c.Trusted || c.Verified, Disabled: c.Disabled,
		HasSecret: c.SecretHash != "", OwnerID: c.OwnerID, Owner: c.Owner, CreatedAt: c.CreatedAt,
	}
}

// CanEditApp 判定"这个人能动这个应用吗"：**只认创建者本人**。
//
// 刻意不为 auth.oauth.manage 开分支：管理台的全量治理是另一条路径上的另一份判定
// （UpdateOAuthClient 等直接判权限码），开发者面不该借道。曾经开过这个分支，
// 后果是管理员在开发者中心看到并改动系统应用与别人的应用。
// 导出是给内存替身用的：归属规则只此一处，替身不能自成一套。
func CanEditApp(actor *User, ownerID string) bool {
	if actor == nil {
		return false
	}
	return ownerID != "" && ownerID == actor.ID
}

// requireAppEditable 把 CanEditApp 翻成对外错误码。别人的应用一律 client_not_found（不是 forbidden）：
// 403 会把"这个 id 确实被别人占了"这个事实透给调用方，而应用 id 是唯一需要保密的标识。
func requireAppEditable(actor *User, app *OAuthClient) error {
	if actor == nil {
		return fmt.Errorf("authentication_required")
	}
	if CanEditApp(actor, app.OwnerID) {
		return nil
	}
	return fmt.Errorf("client_not_found")
}

// ListDeveloperApps 列出"我的应用"：**永远**只回归属当前账号的那些，不分角色。
//
// 条件里必须有 owner_user_id=$1（NULL 永不等于任何值，顺带把 owner 为空的系统应用挡在外面）：
// 管理员的全量视图在管理台（GET /api/admin/oauth/clients），不需要第二份。
func (s *Store) ListDeveloperApps(ctx context.Context, actor *User) ([]DeveloperApp, error) {
	if actor == nil {
		return nil, fmt.Errorf("authentication_required")
	}
	q := "SELECT " + clientColumns + " FROM auth.oauth_clients c LEFT JOIN auth.users u ON u.id=c.owner_user_id" +
		" WHERE c.owner_user_id=$1 ORDER BY c.created_at DESC, c.id"
	rows, err := s.DB.QueryContext(ctx, q, actor.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeveloperApp{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, DeveloperAppOf(c))
	}
	return out, rows.Err()
}

// GetDeveloperApp 读单个应用；不是自己的按"不存在"返回（见 requireAppEditable）。
func (s *Store) GetDeveloperApp(ctx context.Context, id string, actor *User) (*DeveloperApp, error) {
	client, err := s.GetOAuthClient(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := requireAppEditable(actor, client); err != nil {
		return nil, err
	}
	app := DeveloperAppOf(*client)
	return &app, nil
}

// CreateDeveloperApp 自助登记：应用归属调用者，trusted / disabled / verified 一律 false。
// 也就是说，开发者中心登记出来的应用一开始就是"第三方 + 未核验"，
// 想变成自有平台只能由管理员在管理台改（那条路径受 auth.oauth.manage 保护）。
func (s *Store) CreateDeveloperApp(ctx context.Context, in DeveloperAppInput, actor *User) (DeveloperApp, string, error) {
	if actor == nil {
		return DeveloperApp{}, "", fmt.Errorf("authentication_required")
	}
	if err := s.checkDeveloperAppQuota(ctx, actor); err != nil {
		return DeveloperApp{}, "", err
	}
	client, secret, err := s.createOAuthClient(ctx, in.ToClientInput(), actor, actor.ID, false)
	if err != nil {
		return DeveloperApp{}, "", err
	}
	return DeveloperAppOf(client), secret, nil
}

// checkDeveloperAppQuota 判定配额：每个账号一视同仁，管理员也不例外。
//
// 曾经给管理员开了免检分支，理由是"管理台代第三方登记"——那条路根本不走这里（管理台直接
// 调 CreateOAuthClient），于是这个分支只影响"管理员用开发者中心给自己刷应用"。开发者面
// 既然对所有角色只有一条规则（只看 / 只改归属自己的），配额就一并拉平：要批量登记走管理面。
func (s *Store) checkDeveloperAppQuota(ctx context.Context, actor *User) error {
	var n int
	if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM auth.oauth_clients WHERE owner_user_id=$1", actor.ID).Scan(&n); err != nil {
		return err
	}
	if n >= MaxDeveloperAppsPerUser {
		return fmt.Errorf("app_quota_exceeded")
	}
	return nil
}

// UpdateDeveloperApp 改自己的应用。client_id 不可改：它已经写进了对端配置与授权审计，
// 改名可以，改 id 等于换一个应用。管理面字段在 privileged=false 的路径上会被明确拒绝。
func (s *Store) UpdateDeveloperApp(ctx context.Context, id string, in DeveloperAppInput, actor *User) (DeveloperApp, error) {
	in.ID = ""
	client, err := s.updateOAuthClient(ctx, id, in.ToClientInput(), actor, false, func(app *OAuthClient) error {
		return requireAppEditable(actor, app)
	})
	if err != nil {
		return DeveloperApp{}, err
	}
	return DeveloperAppOf(client), nil
}

// RotateDeveloperAppSecret 轮换自己应用的密钥：明文只返回一次，旧密钥立即失效。
func (s *Store) RotateDeveloperAppSecret(ctx context.Context, id string, actor *User) (DeveloperApp, string, error) {
	client, secret, err := s.rotateOAuthClientSecret(ctx, id, actor, func(app *OAuthClient) error {
		return requireAppEditable(actor, app)
	})
	if err != nil {
		return DeveloperApp{}, "", err
	}
	return DeveloperAppOf(client), secret, nil
}

// DeleteDeveloperApp 删除自己登记的应用：授权码与令牌随外键级联删除。
func (s *Store) DeleteDeveloperApp(ctx context.Context, id string, actor *User) error {
	return s.deleteOAuthClient(ctx, id, actor, func(app *OAuthClient) error {
		return requireAppEditable(actor, app)
	})
}

// 核验（verified）没有这里的入口：它是管理面的动作，走 PUT /api/admin/oauth/clients/{id}
// → Store.UpdateOAuthClient。开发者面只读出核验结果（DeveloperApp.Verified），不写。
