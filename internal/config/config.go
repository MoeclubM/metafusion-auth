package config

import (
	"os"
	"strings"
)

// Config 是账号服务的运行配置。RSA 私钥与 issuer/audience 由 token.go 的
// NewTokenIssuerFromEnv 直接读取（AUTH_JWT_PRIVATE_KEY / AUTH_JWT_ISSUER /
// AUTH_JWT_AUDIENCE），与主仓库共用同一份变量名，拆分期间不需要改 .env。
type Config struct {
	Port string
	// DatabaseURL 为必填的 PostgreSQL 连接串，使用账号域独立数据库身份。
	DatabaseURL string
	// 哪些对端算可信反向代理（TRUSTED_PROXIES，默认只信回环+RFC1918 私网）。
	// 空串交给 internal/nettrust 的 Default；"none" 表示入口链上没有代理。
	TrustedProxies string
}

func Load() Config {
	c := Config{
		Port:           env("PORT", "8081"),
		DatabaseURL:    env("DATABASE_URL", ""),
		TrustedProxies: env("TRUSTED_PROXIES", ""),
	}
	return c
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
