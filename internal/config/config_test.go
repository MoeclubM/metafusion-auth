package config

import (
	"net/url"
	"testing"
)

// 口令里出现 @ : / ? # 这类字符时，字符串拼接会拼出非法 DSN 或连错主机；
// 这条用例用"最难缠"的口令固定住转义行为。
func TestBuildDSNEscapesCredentials(t *testing.T) {
	t.Setenv("DB_HOST", "db.internal")
	t.Setenv("DB_PORT", "6543")
	t.Setenv("DB_NAME", "metafusion_db")
	t.Setenv("DB_USER", "metafusion")
	t.Setenv("DB_PASSWORD", "p@ss:w/rd?x#1")
	t.Setenv("DB_SSLMODE", "require")

	parsed, err := url.Parse(buildDSN())
	if err != nil {
		t.Fatalf("拼出的 DSN 不是合法 URL: %v", err)
	}
	if parsed.Scheme != "postgres" {
		t.Fatalf("scheme = %s", parsed.Scheme)
	}
	if parsed.Host != "db.internal:6543" {
		t.Fatalf("host = %s", parsed.Host)
	}
	if parsed.Path != "/metafusion_db" {
		t.Fatalf("path = %s", parsed.Path)
	}
	pass, _ := parsed.User.Password()
	if parsed.User.Username() != "metafusion" || pass != "p@ss:w/rd?x#1" {
		t.Fatalf("凭据转义不正确: user=%s pass=%s", parsed.User.Username(), pass)
	}
	if parsed.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode = %s", parsed.Query().Get("sslmode"))
	}
}

// TRUSTED_PROXIES 必须原样进 Config：main.go 拿它调 nettrust.Apply，
// 读不到就退化成"无可信代理"，限流桶又变成全站共享一个。
func TestLoadReadsTrustedProxies(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.1.0.0/16,203.0.113.7")
	if got := Load().TrustedProxies; got != "10.1.0.0/16,203.0.113.7" {
		t.Fatalf("TrustedProxies = %q，期望原样反映环境变量", got)
	}
}

// 未配置时必须是空串而不是某个硬编码网段：默认值只有 nettrust.Default 一份，别在两处各写一套。
func TestLoadTrustedProxiesDefaultsEmpty(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	if got := Load().TrustedProxies; got != "" {
		t.Fatalf("未配置时 TrustedProxies = %q，期望空串（走 nettrust.Default）", got)
	}
}
