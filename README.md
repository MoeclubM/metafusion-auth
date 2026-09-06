# MetaFusion Auth

MetaFusion 统一身份认证与 IAM 账号中心微服务 (OAuth2.0 / OIDC / JWT)。

## 🔐 核心定位

作为 MetaFusion 生态的独立身份提供商（IdP），负责全域用户的账号注册、密码管理、RBAC 权限分配、OAuth 2.0 授权服务器与无状态 JWT 派发，彻底解耦元数据、论坛与资源存储系统。

- **主项目 (Core Catalog)**: [MetaFusion](https://github.com/MoeclubM/MetaFusion)
- **协议支持**: OAuth 2.0 (Authorization Code + PKCE), OIDC Discovery (`/.well-known/openid-configuration`), RFC 7519 JWT

## 🚀 启动运行

```bash
go run cmd/server/main.go
```
