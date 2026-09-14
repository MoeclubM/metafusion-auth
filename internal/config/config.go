package config

import (
	"os"
	"strings"
)

// Config 是账号服务的运行配置。RSA 私钥与 issuer/audience 由 token.go 的
// NewTokenIssuerFromEnv 直接读取（AUTH_JWT_PRIVATE_KEY / AUTH_JWT_ISSUER /
// AUTH_JWT_AUDIENCE），与主仓库共用同一份变量名，拆分期间不需要改 .env。
type Config struct {
	Port        string
	DatabaseURL string
}

func Load() Config {
	c := Config{Port: env("PORT", "8081"), DatabaseURL: env("DATABASE_URL", "")}
	if c.DatabaseURL == "" {
		c.DatabaseURL = buildDSN()
	}
	return c
}

func buildDSN() string {
	host := env("DB_HOST", "localhost")
	port := env("DB_PORT", "5432")
	name := env("DB_NAME", "metafusion_db")
	user := env("DB_USER", "metafusion")
	pass := os.Getenv("DB_PASSWORD")
	ssl := env("DB_SSLMODE", "disable")
	return "postgres://" + user + ":" + pass + "@" + host + ":" + port + "/" + name + "?sslmode=" + ssl
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
