"use client";

import { ApiError } from "./api";

export type TranslateFn = (key: string, vars?: Record<string, string | number>) => string;

/**
 * 把接口错误翻成如实提示：403 说清缺哪个权限码，5xx / 网络错误说清账号服务不可达，
 * 其余把后端错误码原样带出。绝不把失败伪装成成功。
 */
export function describeApiError(err: unknown, t: TranslateFn, requiredPermission: string): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return t("error.unauthorized");
    if (err.status === 403) return t("error.forbidden", { code: requiredPermission });
    if (err.status === 404) return t("error.notFound");
    if (err.status === 429) return t("error.rateLimited");
    if (err.status >= 502 && err.status <= 504) return t("error.upstream", { status: err.status });
    return t("error.failed", { status: err.status, message: err.message });
  }
  return t("error.network", { message: err instanceof Error ? err.message : String(err) });
}

/**
 * 带头部错误码的版本：账号服务的 respond() 只把 forbidden→403、not_found→404 挑出来，
 * 其余护栏类错误（不能封自己、不能动最后一个管理员…）全部落到 400 + 稳定错误码。
 * 这些码必须逐条翻成人话——裸码对管理员没有意义，把 400 笼统说成"请求失败"又会丢掉唯一有用的信息。
 *
 * codeMap 的键是后端码；值里若含 ":"（如 group_not_found: 组码）则按前缀匹配，冒号后是参数。
 */
export function describeCodedError(
  err: unknown,
  t: TranslateFn,
  requiredPermission: string,
  codeMap: Record<string, string>
): string {
  if (err instanceof ApiError) {
    const raw = (err.message || "").trim();
    if (raw) {
      const key = codeMap[raw];
      if (key) return t(key);
      // 复合码形如 "code: detail"（invalid_permission_code: catalog.x.y、group_not_found: member），
      // 按冒号拆开：前半段定文案，后半段填进 {detail}。
      const sep = raw.indexOf(":");
      if (sep > 0) {
        const head = raw.slice(0, sep).trim();
        const detail = raw.slice(sep + 1).trim();
        const headKey = codeMap[head];
        if (headKey) return t(headKey, { detail });
      }
    }
  }
  return describeApiError(err, t, requiredPermission);
}

/** 用户治理写操作的稳定错误码表（store/identity.go、store/groups.go）。 */
export const USER_ERROR_KEYS: Record<string, string> = {
  cannot_ban_self: "users.err.cannotBanSelf",
  cannot_ban_sole_admin: "users.err.cannotBanSoleAdmin",
  cannot_demote_sole_admin: "users.err.cannotDemoteSoleAdmin",
  invalid_role: "users.err.invalidRole",
  invalid_password_length: "users.err.invalidPasswordLength",
  invalid_credentials_format: "users.err.invalidCredentials",
  user_not_found: "users.err.userNotFound",
  invalid_payload: "users.err.invalidPayload",
  username_or_email_taken: "users.err.usernameTaken",
  group_not_found: "users.err.groupNotFound",
};

/** 权限组与邀请码的稳定错误码表（store/groups.go、store/access.go）。 */
export const GROUP_ERROR_KEYS: Record<string, string> = {
  system_group_immutable: "groups.err.systemImmutable",
  invalid_group_code: "groups.err.invalidCode",
  invalid_permission_code: "groups.err.invalidPermission",
  group_not_found: "groups.err.notFound",
  // 并发建组撞码：后端 ON CONFLICT + groups_code_key 回稳定码 409 group_exists。
  group_exists: "groups.err.exists",
  cannot_strip_admin_wildcard: "groups.err.stripWildcard",
  invalid_payload: "groups.err.invalidPayload",
  forbidden: "groups.err.forbidden",
};

export const INVITE_ERROR_KEYS: Record<string, string> = {
  invite_not_found: "invites.err.notFound",
  invalid_payload: "invites.err.invalidPayload",
  forbidden: "invites.err.forbidden",
};

/** OAuth 客户端管理的稳定错误码表（store/oauth.go）。 */
export const OAUTH_ERROR_KEYS: Record<string, string> = {
  client_not_found: "oauth.err.clientNotFound",
  client_exists: "oauth.err.clientExists",
  invalid_client: "oauth.err.invalidClient",
  invalid_client_id: "oauth.err.invalidClientId",
  invalid_client_name: "oauth.err.invalidClientName",
  invalid_redirect_uris: "oauth.err.invalidRedirectUris",
  invalid_redirect_uri: "oauth.err.invalidRedirectUri",
  invalid_scope: "oauth.err.invalidScope",
  invalid_scopes: "oauth.err.invalidScope",
  seeded_client_immutable: "oauth.err.seededClientImmutable",
  forbidden: "oauth.err.forbidden",
  invalid_payload: "oauth.err.invalidPayload",
};
