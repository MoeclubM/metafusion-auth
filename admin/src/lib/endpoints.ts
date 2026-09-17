"use client";

// 账号服务（metafusion-auth）管理面契约的薄封装。
//
// 契约来源（只读核对，本应用不改账号服务代码）：
//   internal/handler/handler.go         —— 路由与响应形状
//   internal/handler/oauth_admin.go     —— OAuth 客户端管理面
//   internal/store/{store,groups,access,oauth}.go —— DTO 与稳定错误码
//
// 边界：账号服务只负责"存组、存权限码、算出权限集合"，**不解释权限码的含义**。
// 本模块同样不解释，只把接口给的 service 前缀原样透出。

import { apiFetch, getJson, sendJson } from "./api";

// ── DTO ──

/** /api/auth/me 的账号投影；password_hash 永不出现在 JSON 里。 */
export interface MeUser {
  id: string;
  username: string;
  email?: string;
  role?: string;
  groups?: string[];
  /** 展开后的权限码集合；含 * 即全权。授权判定以它为准。 */
  permissions?: string[];
  banned?: boolean;
}

export interface AdminUser extends MeUser {}

/** 权限组：一份权限码集合 + 四语显示名。is_system 的组可改权限但不可删。 */
export interface AdminGroup {
  id?: string;
  code: string;
  names?: Record<string, string>;
  descriptions?: Record<string, string>;
  permissions?: string[];
  is_system?: boolean;
  sort_order?: number;
}

/** 权限码清单项：service 是所属子系统前缀（auth / catalog / community / storage）。 */
export interface AdminPermissionCode {
  code: string;
  service?: string;
  names?: Record<string, string>;
  descriptions?: Record<string, string>;
}

export interface AdminInvite {
  code: string;
  created_by?: string;
  creator?: string;
  note?: string;
  max_uses: number;
  used_count: number;
  revoked: boolean;
  expires_at?: string;
  created_at?: string;
}

/** 客户端投影：不含密钥哈希（服务端 SecretHash 的 json tag 为 "-"）。 */
export interface OAuthClient {
  client_id: string;
  name: string;
  description?: string;
  homepage_url?: string;
  redirect_uris: string[];
  scopes: string[];
  trusted: boolean;
  disabled: boolean;
  /** 核验状态：同意页对未核验的第三方应用会多显示一条提示。 */
  verified: boolean;
  /** 归属账号 id：**空 = 平台登记的系统应用**（服务端 json tag 是 omitempty，NULL 时这个键不出现）。 */
  owner_user_id?: string;
  owner_username?: string;
  created_at: string;
}

/**
 * isSystemClient 判定"这是平台自己登记的系统应用"（第一方）。
 *
 * 依据是**归属**，不是"是否种子"、也不是 trust：管理面列表 GET /api/admin/oauth/clients 回的
 * 是 store.OAuthClient 投影（internal/store/oauth.go），它的字段里根本没有 first_party——那是
 * 开发者中心 DeveloperApp 的字段；服务端另有 OAuthClient.FirstParty()，那个方法只是 trusted 的
 * 别名。而 owner_user_id 为空恰好就是这个事实本身：Init 的三个种子客户端插入时不写
 * owner_user_id（internal/store/store.go），开发者中心自助登记的应用必然带 owner_user_id
 * （internal/store/developer.go 读、改、轮换、删四条路径都按它过滤）。因此
 * "没有归属" = 系统应用（只能在这里维护），"有归属" = 第三方自助登记的应用。
 */
export function isSystemClient(client: OAuthClient): boolean {
  return !client.owner_user_id;
}

/**
 * 服务端 Init 每次启动都按 id 复活这三行（internal/store/oauth.go 的 seededClientIDs），
 * 删除必然被拒（seeded_client_immutable）——界面提前置灰并说明，而不是让用户点了才报错。
 * 它只说明"删不掉这几行"，**不**代表"谁是系统应用"（系统应用看归属，见 isSystemClient）。
 */
export const SEEDED_CLIENT_IDS = new Set(["metafusion-catalog", "metafusion-forum", "metafusion-resources"]);

/** 创建 / 轮换的响应：client_secret 是**一次性明文**，离开这一次响应就无处可取。 */
export interface OAuthClientSecret {
  client: OAuthClient;
  client_secret: string;
}

/** 写入形状：字段缺省即"不改这一项"（服务端用指针区分没传与传了零值）。 */
export interface OAuthClientDraft {
  client_id?: string;
  name?: string;
  redirect_uris?: string[];
  scopes?: string[];
  trusted?: boolean;
  disabled?: boolean;
  /** 核验状态：只有管理面（PUT /api/admin/oauth/clients/{id}）写得了；开发者路径传它会被拒。 */
  verified?: boolean;
}

/** 实例设置是后端返回的键值补丁：键与类型都由接口决定，前端不维护字段清单。 */
export type SettingsMap = Record<string, unknown>;

/** 角色枚举取自 store/identity.go 的校验分支，名单外的值只会拿回 invalid_role。 */
export const ADMIN_ROLES = ["user", "editor", "admin"] as const;

/** 受支持的 scope，与 store.SupportedScopes 一致；界面只从这里出选项。 */
export const OAUTH_SCOPES = ["openid", "profile", "email"] as const;

/** client_id 形状与 store.ValidClientID 同口径。 */
export const OAUTH_CLIENT_ID_RE = /^[a-z][a-z0-9_-]{2,63}$/;

/** 组码格式来自接口约束（store/access.go：^[a-z][a-z0-9_-]{1,63}$）。 */
export const GROUP_CODE_RE = /^[a-z][a-z0-9_-]{1,63}$/;

/** 权限码格式与 store.ValidPermissionCode 同口径：* 或 服务.资源.动作（最多四段）。 */
export const PERMISSION_CODE_RE = /^\*$|^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$/;

export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 72;

// ── 会话 ──

/** 探活：401 的处置权交给 SessionProvider（它统一跳登录页），这里不抢先跳。 */
export function fetchMe(): Promise<MeUser> {
  return apiFetch<MeUser>("/api/auth/me", {}, { redirectOn401: false });
}

export function logout(): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>("/api/auth/logout", "POST");
}

// ── 用户治理 ──

export async function fetchAdminUsers(): Promise<AdminUser[]> {
  const res = await getJson<{ items?: AdminUser[] }>("/api/admin/users");
  return res.items ?? [];
}

/** 建号：邮箱可留空，服务端会用 `<username>@findverse.cc` 兜底。 */
export function createAdminUser(input: { username: string; email?: string; password: string }): Promise<AdminUser> {
  return sendJson<AdminUser>("/api/admin/users", "POST", {
    username: input.username,
    email: input.email ?? "",
    password: input.password,
  });
}

/**
 * 改角色是**写透两处的**：store.UpdateUserRole 先把该用户的组成员关系全删掉，再按
 * RoleToGroups 重建（admin → admin；editor → catalog_editor, member；其余 → member）。
 * 手工分配的权限组因此会被角色默认组覆盖——界面必须在提交前讲清这件事。
 */
export function updateUserRole(userId: string, role: string): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>(`/api/admin/users/${encodeURIComponent(userId)}/role`, "PUT", { role });
}

/** 重置密码：服务端只认 12–72 位（store.ResetUserPassword）。 */
export function resetUserPassword(userId: string, password: string): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>(`/api/admin/users/${encodeURIComponent(userId)}/password`, "PUT", { password });
}

/** 覆盖式写入：传空数组即清空该用户的全部组。 */
export function setUserGroups(userId: string, groups: string[]): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>(`/api/admin/users/${encodeURIComponent(userId)}/groups`, "PUT", { groups });
}

/** 封禁/解封同一端点；响应回的是保存后的账号投影，界面据此刷新该行而不是猜结果。 */
export function setUserBanned(userId: string, banned: boolean): Promise<{ ok: boolean; user?: AdminUser }> {
  return sendJson<{ ok: boolean; user?: AdminUser }>(`/api/admin/users/${encodeURIComponent(userId)}/ban`, "PUT", { banned });
}

// ── 权限组与权限码 ──

export async function fetchAdminGroups(): Promise<AdminGroup[]> {
  const res = await getJson<{ items?: AdminGroup[] }>("/api/admin/groups");
  return res.items ?? [];
}

export async function fetchAdminPermissions(): Promise<AdminPermissionCode[]> {
  const res = await getJson<{ items?: AdminPermissionCode[] }>("/api/admin/permissions");
  return res.items ?? [];
}

export function createAdminGroup(group: AdminGroup): Promise<AdminGroup> {
  return sendJson<AdminGroup>("/api/admin/groups", "POST", group);
}

/** 组码不可改：它是路由参数与成员关系的锚点，所以 body 里不带 code。 */
export function updateAdminGroup(code: string, group: AdminGroup): Promise<AdminGroup> {
  return sendJson<AdminGroup>(`/api/admin/groups/${encodeURIComponent(code)}`, "PUT", {
    names: group.names ?? {},
    descriptions: group.descriptions ?? {},
    permissions: group.permissions ?? [],
    sort_order: group.sort_order ?? 0,
  });
}

export function deleteAdminGroup(code: string): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>(`/api/admin/groups/${encodeURIComponent(code)}`, "DELETE");
}

// ── 邀请码 ──

export async function fetchAdminInvites(): Promise<AdminInvite[]> {
  const res = await getJson<{ items?: AdminInvite[] }>("/api/admin/invites");
  return res.items ?? [];
}

export function createAdminInvite(input: { note?: string; max_uses?: number; expires_in_days?: number }): Promise<AdminInvite> {
  return sendJson<AdminInvite>("/api/admin/invites", "POST", {
    note: input.note ?? "",
    max_uses: input.max_uses ?? 0,
    expires_in_days: input.expires_in_days ?? 0,
  });
}

export function revokeAdminInvite(code: string): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>(`/api/admin/invites/${encodeURIComponent(code)}/revoke`, "POST");
}

// ── 实例设置（只读页用） ──

export function fetchAdminSettings(): Promise<SettingsMap> {
  return getJson<SettingsMap>("/api/admin/settings");
}

// ── OAuth 客户端 ──

export async function fetchOAuthClients(): Promise<OAuthClient[]> {
  const res = await getJson<{ items?: OAuthClient[] }>("/api/admin/oauth/clients");
  return res.items ?? [];
}

export function createOAuthClient(draft: OAuthClientDraft): Promise<OAuthClientSecret> {
  return sendJson<OAuthClientSecret>("/api/admin/oauth/clients", "POST", draft);
}

/** PUT 对服务端是补丁语义：多传的字段就等于改了它，所以只提交改动过的键。 */
export function updateOAuthClient(id: string, patch: OAuthClientDraft): Promise<OAuthClient> {
  return sendJson<{ client: OAuthClient }>(`/api/admin/oauth/clients/${encodeURIComponent(id)}`, "PUT", patch).then(
    (res) => res.client
  );
}

export function rotateOAuthClientSecret(id: string): Promise<OAuthClientSecret> {
  return sendJson<OAuthClientSecret>(`/api/admin/oauth/clients/${encodeURIComponent(id)}/rotate-secret`, "POST");
}

export function deleteOAuthClient(id: string): Promise<{ ok: boolean }> {
  return sendJson<{ ok: boolean }>(`/api/admin/oauth/clients/${encodeURIComponent(id)}`, "DELETE");
}
