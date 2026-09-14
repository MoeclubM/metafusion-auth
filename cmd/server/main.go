package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/MoeclubM/metafusion-auth/internal/config"
	"github.com/MoeclubM/metafusion-auth/internal/handler"
	"github.com/MoeclubM/metafusion-auth/internal/store"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("auth database connection failed: %v", err)
	}
	defer s.Close()
	if err = s.Init(ctx); err != nil {
		log.Fatalf("auth schema initialization failed: %v", err)
	}

	// 无状态访问令牌：配置 AUTH_JWT_PRIVATE_KEY 时用持久 RSA 私钥签发 RS256 JWT；
	// 未配置则生成进程内临时密钥（重启即失效，靠查库兜底），保证服务仍可启动。
	issuer, err := store.NewTokenIssuerFromEnv(env("AUTH_JWT_ISSUER", "https://findverse.cc/api"), env("AUTH_JWT_AUDIENCE", "metafusion"))
	if err != nil {
		log.Fatalf("auth token issuer initialization failed: %v", err)
	}
	s.Tokens = issuer
	if issuer.Ephemeral() {
		log.Print("AUTH_JWT_PRIVATE_KEY is unset; using an in-process RSA key (tokens expire on restart)")
	}
	// issuer 与 audience 对所有依赖方必须完全一致，否则已签发的令牌全部失效。
	log.Printf("auth issuer=%s audience=%s", issuer.Issuer(), issuer.Audience())

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.SetTrustedProxies(nil)
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		// 切流自检用：响应头标明是哪个服务答复的，便于确认网关把前缀切到了目标上游。
		c.Header("X-MetaFusion-Service", "metafusion-auth")
		c.Next()
	})

	handler.New(s).Register(r)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "live", "service": "metafusion-auth"})
	})
	r.GET("/ready", func(c *gin.Context) {
		check, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := s.DB.PingContext(check); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready", "dependencies": []string{"postgres"}})
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	done := make(chan error, 1)
	go func() {
		log.Print("MetaFusion auth service ready")
		done <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Fatalf("server shutdown error: %v", err)
		}
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		log.Fatalf("server error: %v", err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
