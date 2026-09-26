import type { MeUser } from "./endpoints";

// 权限码：账号服务持有全量码表并装进权限组，各子系统解释自己那些码。
// 本应用只用到账号域的六条；判定与账号服务 store.Can 逐字同口径。

export const AUTH_USERS_MANAGE = "auth.users.manage";
export const AUTH_GROUPS_MANAGE = "auth.groups.manage";
export const AUTH_INVITES_MANAGE = "auth.invites.manage";
export const AUTH_SETTINGS_MANAGE = "auth.settings.manage";
export const AUTH_OAUTH_MANAGE = "auth.oauth.manage";
/** 审计读取面：跨服务审计表（audit.audit_log）的唯一读取端点，见 docs/architecture/audit-log.md §5。 */
export const AUTH_AUDIT_READ = "auth.audit.read";

/**
 * can 判定"这个身份持有某个权限码吗"。
 *
 * 一律以服务端返回的 permissions 为准（含 * 通配）——前端判定只是"看不见"的界面收敛，
 * 不替代服务端鉴权：服务端的 requirePermission 才是唯一授权断言。
 * permissions 为空时不授予权限，与 store.Can 一致。
 */
export function can(user: MeUser | null | undefined, code: string): boolean {
  if (!user) return false;
  const perms = user.permissions ?? [];
  return perms.includes("*") || perms.includes(code);
}

/** 各管理面需要的码，也是导航与降级判定的唯一来源。 */
export const SECTION_PERMISSIONS = {
  users: AUTH_USERS_MANAGE,
  groups: AUTH_GROUPS_MANAGE,
  invites: AUTH_INVITES_MANAGE,
  oauth: AUTH_OAUTH_MANAGE,
  instance: AUTH_SETTINGS_MANAGE,
  audit: AUTH_AUDIT_READ,
} as const;

export type SectionKey = keyof typeof SECTION_PERMISSIONS;

/** 能否进入本管理台：任一管理码命中。 */
export function canEnterAdmin(user: MeUser | null | undefined): boolean {
  return (Object.values(SECTION_PERMISSIONS) as string[]).some((code) => can(user, code));
}
