package config

import (
	"net/url"
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

// buildDSN 用 url.URL 拼连接串：口令里的 @ : / ? # 等字符必须转义，
// 直接字符串拼接会在这些字符上拼出非法 DSN（或连错主机）。
func buildDSN() string {
	u := url.URL{
		Scheme: "postgres",
		Host:   env("DB_HOST", "localhost") + ":" + env("DB_PORT", "5432"),
		Path:   env("DB_NAME", "metafusion_db"),
		User:   url.UserPassword(env("DB_USER", "metafusion"), os.Getenv("DB_PASSWORD")),
	}
	q := u.Query()
	q.Set("sslmode", env("DB_SSLMODE", "disable"))
	u.RawQuery = q.Encode()
	return u.String()
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
