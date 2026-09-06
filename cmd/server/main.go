package main

import (
    "log"
    "os"
    "github.com/gin-gonic/gin"
    "github.com/MoeclubM/metafusion-auth/internal/handler"
)

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8081"
    }

    r := gin.Default()

    // Health check
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok", "service": "metafusion-auth"})
    })

    // OIDC Discovery
    r.GET("/.well-known/openid-configuration", handler.OIDCDiscovery)
    r.GET("/.well-known/jwks.json", handler.JWKS)

    // API Routes
    api := r.Group("/api/auth")
    {
        api.POST("/register", handler.Register)
        api.POST("/login", handler.Login)
        api.POST("/logout", handler.Logout)
        api.POST("/refresh", handler.RefreshToken)
        api.GET("/me", handler.GetCurrentUser)

        // OAuth2.0 Server Endpoints
        oauth := api.Group("/oauth")
        {
            oauth.GET("/authorize", handler.OAuthAuthorize)
            oauth.POST("/token", handler.OAuthToken)
            oauth.POST("/revoke", handler.OAuthRevoke)
        }
    }

    log.Printf("MetaFusion Auth Service listening on port %s", port)
    if err := r.Run(":" + port); err != nil {
        log.Fatalf("Failed to run server: %v", err)
    }
}
