package handler

// 同意页：服务端渲染 HTML（而不是跳账号前端页面）。选择理由：
//
//  1. 授权请求本身就是浏览器顶层跳转，页面放在本服务里就不依赖前端站点是否部署或可达，
//     第三方站点与本地开发端口都是同一套行为；
//  2. 不需要在主仓库新增页面/路由（本次改动只涉及账号服务），也不引入新的跨站约定：
//     AUTH_ACCOUNT_URL 只用于"未登录跳登录页"，登录回来仍是 /api/oauth/authorize；
//  3. 页面只有两条链接（consent=allow / consent=deny），而会话 Cookie 是 SameSite=Strict，
//     跨站发起的请求根本不带会话，因此不存在"别的站点替你点同意"的 CSRF 面。
//
// 文案四语齐备（Accept-Language 选语言，匹配不到回落 en-US，不拿中文兜底）；
// 新增受支持的 scope 时必须同步补文案，consent_test.go 会拦住漏掉的项。

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/store"
)

// consentScopeText 是单个 scope 在同意页上的展示文案。
type consentScopeText struct {
	Name string
	Desc string
}

// consentText 是一种语言的固定文案。
type consentText struct {
	HTMLTitle   string
	Heading     string
	ClientLbl   string
	RedirectLbl string
	AllowLbl    string
	DenyLbl     string
	Footnote    string
	// UnverifiedNotice 是「该应用未通过核验」的提示：只对未核验的第三方应用出现，
	// 自有平台（免同意）与已核验的应用都不显示这一行。
	UnverifiedNotice string
	Scopes           map[string]consentScopeText
}

var consentTexts = map[string]consentText{
	"zh-CN": {
		HTMLTitle:        "授权访问账号",
		Heading:          "授权访问你的 MetaFusion 账号",
		ClientLbl:        "请求方",
		RedirectLbl:      "授权后跳转回",
		AllowLbl:         "同意并继续",
		DenyLbl:          "拒绝",
		UnverifiedNotice: "该应用尚未通过核验。请确认你信任它的来源，再决定是否授权。",
		Footnote:         "同意后授权码会发回上面的地址。你可以在账号页查看与撤销授权；管理员也可以在管理台吊销该客户端的令牌。",
		Scopes: map[string]consentScopeText{
			"openid":  {Name: "确认你的身份", Desc: "返回你的账号 ID（sub）"},
			"profile": {Name: "读取基本资料", Desc: "用户名与角色"},
			"email":   {Name: "读取邮箱", Desc: "你的账号邮箱地址"},
		},
	},
	"zh-TW": {
		HTMLTitle:        "授權存取帳號",
		Heading:          "授權存取你的 MetaFusion 帳號",
		ClientLbl:        "請求方",
		RedirectLbl:      "授權後跳轉回",
		AllowLbl:         "同意並繼續",
		DenyLbl:          "拒絕",
		UnverifiedNotice: "此應用程式尚未通過驗證。請確認你信任它的來源，再決定是否授權。",
		Footnote:         "同意後授權碼會傳回上面的位址。你可以在帳號頁檢視與撤銷授權；管理員也可以在管理後台撤銷該用戶端的權杖。",
		Scopes: map[string]consentScopeText{
			"openid":  {Name: "確認你的身分", Desc: "回傳你的帳號 ID（sub）"},
			"profile": {Name: "讀取基本資料", Desc: "使用者名稱與角色"},
			"email":   {Name: "讀取電子郵件", Desc: "你的帳號電子郵件地址"},
		},
	},
	"ja-JP": {
		HTMLTitle:        "アカウントへのアクセス許可",
		Heading:          "MetaFusion アカウントへのアクセスを許可",
		ClientLbl:        "要求元",
		RedirectLbl:      "許可後に戻る先",
		AllowLbl:         "許可して続行",
		DenyLbl:          "拒否",
		UnverifiedNotice: "このアプリはまだ検証されていません。提供元を信頼できるか確認してから許可してください。",
		Footnote:         "許可すると認可コードが上記のアドレスに返されます。アカウントページで確認・取り消しができ、管理者は管理画面でこのクライアントのトークンを取り消せます。",
		Scopes: map[string]consentScopeText{
			"openid":  {Name: "本人確認", Desc: "アカウント ID（sub）を返します"},
			"profile": {Name: "プロフィールの読み取り", Desc: "ユーザー名とロール"},
			"email":   {Name: "メールアドレスの読み取り", Desc: "アカウントのメールアドレス"},
		},
	},
	"en-US": {
		HTMLTitle:        "Authorize account access",
		Heading:          "Authorize access to your MetaFusion account",
		ClientLbl:        "Requested by",
		RedirectLbl:      "Redirects to",
		AllowLbl:         "Allow",
		DenyLbl:          "Deny",
		UnverifiedNotice: "This app has not been verified yet. Make sure you trust where it came from before you allow access.",
		Footnote:         "An authorization code is sent back to the address above after you allow. You can review and revoke this authorization from your account page; an administrator can also revoke the client's tokens in the admin console.",
		Scopes: map[string]consentScopeText{
			"openid":  {Name: "Verify your identity", Desc: "Returns your account ID (sub)"},
			"profile": {Name: "Read your basic profile", Desc: "Username and role"},
			"email":   {Name: "Read your email address", Desc: "The email on your account"},
		},
	},
}

// consentScopeView 是模板里的 scope 行。
type consentScopeView struct {
	Code string
	Name string
	Desc string
}

// consentView 是模板数据。所有会进 HTML 的字段都由 html/template 转义，
// 同意 / 拒绝链接通过 href 输出，同样会被做 URL 属性转义。
type consentView struct {
	Lang        string
	HTMLTitle   string
	Heading     string
	ClientLbl   string
	RedirectLbl string
	ClientName  string
	ClientID    string
	RedirectURI string
	Scopes      []consentScopeView
	AllowLbl    string
	DenyLbl     string
	AllowURL    string
	DenyURL     string
	Footnote    string
	// UnverifiedNotice 为空表示不显示提示条。
	UnverifiedNotice string
}

// consentTextFor 按 Accept-Language 选文案：先按出现顺序做标签精确匹配，
// 再按语言前缀兜底（zh-Hant/zh-HK → zh-TW，其它 zh → zh-CN），最后回落 en-US。
func consentTextFor(header string) (string, consentText) {
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if tag == "" {
			continue
		}
		for _, lang := range []string{"zh-CN", "zh-TW", "ja-JP", "en-US"} {
			if strings.EqualFold(lang, tag) {
				return lang, consentTexts[lang]
			}
		}
		lower := strings.ToLower(tag)
		switch {
		case strings.HasPrefix(lower, "zh-tw"), strings.HasPrefix(lower, "zh-hant"), strings.HasPrefix(lower, "zh-hk"):
			return "zh-TW", consentTexts["zh-TW"]
		case strings.HasPrefix(lower, "zh"):
			return "zh-CN", consentTexts["zh-CN"]
		case strings.HasPrefix(lower, "ja"):
			return "ja-JP", consentTexts["ja-JP"]
		case strings.HasPrefix(lower, "en"):
			return "en-US", consentTexts["en-US"]
		}
	}
	return "en-US", consentTexts["en-US"]
}

// renderConsent 渲染同意页。同意 / 拒绝链接是在**同一个**授权请求上追加
// consent=allow|deny，因此 state、PKCE 参数与 scope 都原样回到这一次请求上。
func (h *Handler) renderConsent(c *gin.Context, client *store.OAuthClient, granted []string) {
	lang, text := consentTextFor(c.GetHeader("Accept-Language"))
	withConsent := func(value string) string {
		q := c.Request.URL.Query()
		q.Set("consent", value)
		return c.Request.URL.Path + "?" + q.Encode()
	}
	view := consentView{
		Lang:        lang,
		HTMLTitle:   text.HTMLTitle,
		Heading:     text.Heading,
		ClientLbl:   text.ClientLbl,
		RedirectLbl: text.RedirectLbl,
		ClientName:  client.Name,
		ClientID:    client.ID,
		RedirectURI: c.Query("redirect_uri"),
		AllowLbl:    text.AllowLbl,
		DenyLbl:     text.DenyLbl,
		AllowURL:    withConsent("allow"),
		DenyURL:     withConsent("deny"),
		Footnote:    text.Footnote,
	}
	// 未核验提示只对第三方未核验应用出现：自有平台免同意、已核验应用都不需要这一行。
	if !client.Trusted && !client.Verified {
		view.UnverifiedNotice = text.UnverifiedNotice
	}
	for _, code := range granted {
		item := text.Scopes[code]
		view.Scopes = append(view.Scopes, consentScopeView{Code: code, Name: item.Name, Desc: item.Desc})
	}
	// 这是要用户做"授权"决定的一页：禁止被 frame、禁止缓存，页面自身只允许内联样式。
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := consentTemplate.Execute(c.Writer, view); err != nil {
		// 模板是编译期固定的，走到这里说明写响应已失败：记状态即可，不再尝试输出 HTML。
		c.Status(http.StatusInternalServerError)
	}
}

// consentTemplate 是一页静态结构：没有脚本、没有表单（两个按钮是普通链接），
// 因此 CSP 可以收紧到 default-src 'none'。
var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="{{.Lang}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.HTMLTitle}}</title>
<style>
  :root { color-scheme: dark }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: #0b0b0f; color: #e8e8ef;
         font-family: system-ui, -apple-system, "Segoe UI", "Noto Sans CJK SC", sans-serif }
  main { width: min(28rem, 92vw); padding: 1.75rem; border: 1px solid rgba(255,255,255,.12);
         border-radius: 14px; background: rgba(255,255,255,.03) }
  h1 { font-size: 1.125rem; margin: 0 0 1.1rem }
  ul { list-style: none; margin: 0 0 1rem; padding: 0 }
  li { padding: .6rem .75rem; border: 1px solid rgba(255,255,255,.08); border-radius: 10px; margin-bottom: .5rem }
  li b { display: block; font-size: .9rem; font-weight: 600 }
  li span { color: #a5a5b3; font-size: .82rem }
  dl { margin: 0 0 1.1rem; font-size: .8rem; color: #a5a5b3 }
  dt { margin-top: .5rem }
  dd { margin: .15rem 0 0; color: #e8e8ef; word-break: break-all }
  p.warn { margin: 0 0 1rem; padding: .5rem .75rem; border-radius: 10px; font-size: .8rem; line-height: 1.5;
           background: rgba(245,158,11,.12); border: 1px solid rgba(245,158,11,.35); color: #fbbf24 }
  .row { display: flex; gap: .6rem }
  a.btn { flex: 1; text-align: center; text-decoration: none; padding: .6rem .75rem;
          border-radius: 10px; font-size: .9rem }
  a.allow { background: #4c7dff; color: #fff }
  a.deny { border: 1px solid rgba(255,255,255,.18); color: #e8e8ef }
  small { display: block; margin-top: 1rem; color: #8b8b99; font-size: .75rem; line-height: 1.5 }
</style>
</head>
<body>
<main>
  <h1>{{.Heading}}</h1>
  <ul>
  {{range .Scopes}}  <li><b>{{.Name}}</b><span>{{.Desc}}</span></li>
  {{end}}</ul>
  <dl>
    <dt>{{.ClientLbl}}</dt><dd>{{.ClientName}} ({{.ClientID}})</dd>
    <dt>{{.RedirectLbl}}</dt><dd>{{.RedirectURI}}</dd>
  </dl>
  {{if .UnverifiedNotice}}<p class="warn">{{.UnverifiedNotice}}</p>{{end}}
  <div class="row">
    <a class="btn deny" href="{{.DenyURL}}" rel="nofollow">{{.DenyLbl}}</a>
    <a class="btn allow" href="{{.AllowURL}}" rel="nofollow">{{.AllowLbl}}</a>
  </div>
  <small>{{.Footnote}}</small>
</main>
</body>
</html>
`))
