package config

import (
	"testing"
)

func TestLoadRequiresExplicitDatabaseURL(t *testing.T) {
	t.Setenv("DB_HOST", "db.internal")
	t.Setenv("DB_PORT", "6543")
	t.Setenv("DB_NAME", "metafusion_db")
	t.Setenv("DB_USER", "metafusion")
	t.Setenv("DB_PASSWORD", "test-only-password")
	t.Setenv("DB_SSLMODE", "require")
	t.Setenv("DATABASE_URL", " \t ")
	if got := Load().DatabaseURL; got != "" {
		t.Fatalf("缺少 DATABASE_URL 时不得读取 DB_*，got=%q", got)
	}

	const dsn = "postgres://mf_auth:test-only-password@db.internal:6543/metafusion_db?sslmode=require"
	t.Setenv("DATABASE_URL", " \t"+dsn+"\n")
	if got := Load().DatabaseURL; got != dsn {
		t.Fatalf("DatabaseURL = %q，期望显式配置", got)
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
