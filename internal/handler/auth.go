package handler

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

func OIDCDiscovery(c *gin.Context) {
    issuer := "https://findverse.cc"
    c.JSON(http.StatusOK, gin.H{
        "issuer":                                issuer,
        "authorization_endpoint":                issuer + "/api/auth/oauth/authorize",
        "token_endpoint":                        issuer + "/api/auth/oauth/token",
        "userinfo_endpoint":                     issuer + "/api/auth/me",
        "jwks_uri":                              issuer + "/.well-known/jwks.json",
        "response_types_supported":             []string{"code", "token"},
        "subject_types_supported":              []string{"public"},
        "id_token_signing_alg_values_supported": []string{"RS256", "HS256"},
        "scopes_supported":                      []string{"openid", "profile", "email", "catalog:read", "catalog:edit", "storage:download", "community:post"},
    })
}

func JWKS(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"keys": []any{}})
}

func Register(c *gin.Context) {
    c.JSON(http.StatusNotImplemented, gin.H{"message": "Auth service scaffold ready"})
}

func Login(c *gin.Context) {
    c.JSON(http.StatusNotImplemented, gin.H{"message": "Auth service scaffold ready"})
}

func Logout(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

func RefreshToken(c *gin.Context) {
    c.JSON(http.StatusNotImplemented, gin.H{"message": "Auth service scaffold ready"})
}

func GetCurrentUser(c *gin.Context) {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

func OAuthAuthorize(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "oauth_authorize_endpoint"})
}

func OAuthToken(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "oauth_token_endpoint"})
}

func OAuthRevoke(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
