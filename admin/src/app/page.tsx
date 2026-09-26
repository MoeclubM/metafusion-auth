"use client";

// 用户治理：列表 / 搜索 / 改角色 / 改密码 / 封禁解封 / 权限组分配。
//
// 两个只读来源所需权限不同（成员列表要 auth.users.manage、权限组清单要 auth.groups.manage），
// 所以各自独立取数：任一 403 只让它自己那块降级，不能把整页拖黑。
//
// 角色与权限组是同一份事实的两处投影：账号服务的 UpdateUserRole 会把成员关系整组删掉再按
// RoleToGroups 重建，手工分配的自定义组因此会被覆盖。界面不藏这个副作用——改角色时直接
// 锁住组选择并写明原因，而不是先提交再让管理员发现权限没了。

import React, { useMemo, useState } from "react";
import { Ban, KeyRound, Plus, RefreshCw, Search, ShieldCheck, UserCheck, UserCog, Users } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useSession } from "@/lib/session";
import { useResource } from "@/lib/useResource";
import { AUTH_GROUPS_MANAGE, AUTH_USERS_MANAGE } from "@/lib/permissions";
import { describeCodedError, USER_ERROR_KEYS } from "@/lib/errors";
import { sortGroups } from "@/lib/format";
import {
  createAdminUser,
  fetchAdminGroups,
  fetchAdminUsers,
  MAX_PASSWORD,
  MIN_PASSWORD,
  resetUserPassword,
  setUserBanned,
  setUserGroups,
  type AdminGroup,
  type AdminUser,
} from "@/lib/endpoints";
import { RequirePermission } from "@/components/PermissionGate";
import { CancelButton, ConfirmDialog, Modal } from "@/components/ui/Modal";
import {
  Chip,
  EmptyBlock,
  ErrorNotice,
  inputClass,
  labelClass,
  LoadingBlock,
  primaryButtonClass,
  RefreshButton,
  SectionHeader,
  StatusMessage,
} from "@/components/ui/blocks";

// 模块级常量：useResource 的 initial 必须是稳定引用，否则会反复重新取数。
const EMPTY_USERS: AdminUser[] = [];
const EMPTY_GROUPS: AdminGroup[] = [];

function sameGroupSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((code) => set.has(code));
}

function UsersPanel() {
  const { t } = useI18n();
  const { user: me } = useSession();

  const users = useResource(fetchAdminUsers, EMPTY_USERS, AUTH_USERS_MANAGE);
  const groups = useResource(fetchAdminGroups, EMPTY_GROUPS, AUTH_GROUPS_MANAGE);

  const [query, setQuery] = useState("");
  const [editing, setEditing] = useState<AdminUser | null>(null);
  const [form, setForm] = useState<{ password: string; groups: string[] }>({
    password: "",
    groups: [],
  });
  const [banTarget, setBanTarget] = useState<AdminUser | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState({ username: "", email: "", password: "" });
  const [creating, setCreating] = useState(false);

  const groupList = useMemo(() => sortGroups(groups.data), [groups.data]);

  const normalizedQuery = query.trim().toLowerCase();
  const visibleUsers = users.data.filter((u) => {
    if (!normalizedQuery) return true;
    return (
      (u.username ?? "").toLowerCase().includes(normalizedQuery) ||
      (u.email ?? "").toLowerCase().includes(normalizedQuery) ||
      u.id.toLowerCase().includes(normalizedQuery)
    );
  });

  const groupsChanged = editing != null && !sameGroupSet(form.groups, editing.groups ?? []);
  const wantsPassword = form.password !== "";
  const passwordTooShort = wantsPassword && (form.password.length < MIN_PASSWORD || form.password.length > MAX_PASSWORD);

  const openEditor = (u: AdminUser) => {
    setEditing(u);
    setForm({ password: "", groups: [...(u.groups ?? [])] });
    setMessage(null);
  };

  const closeEditor = () => {
    setEditing(null);
    setMessage(null);
  };

  const toggleGroup = (code: string) => {
    setForm((prev) => ({
      ...prev,
      groups: prev.groups.includes(code) ? prev.groups.filter((c) => c !== code) : [...prev.groups, code],
    }));
  };

  const applyChanges = async () => {
    if (!editing) return;
    setBusy(true);
    setMessage(null);
    try {
      if (wantsPassword) await resetUserPassword(editing.id, form.password);
      if (groupsChanged) await setUserGroups(editing.id, form.groups);
      setEditing(null);
      setMessage({ kind: "ok", text: t("users.saveSuccess") });
      // 组成员关系以服务端返回为准。
      users.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_USERS_MANAGE, USER_ERROR_KEYS) });
    } finally {
      setBusy(false);
    }
  };

  const handleSave = () => {
    if (busy || !editing) return;
    if (passwordTooShort) {
      setMessage({ kind: "err", text: t("users.passwordTooShort") });
      return;
    }
    if (!groupsChanged && !wantsPassword) {
      setMessage({ kind: "err", text: t("users.noChanges") });
      return;
    }
    void applyChanges();
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setMessage(null);
    try {
      await createAdminUser({
        username: createForm.username.trim(),
        email: createForm.email.trim(),
        password: createForm.password,
      });
      setCreateForm({ username: "", email: "", password: "" });
      setCreateOpen(false);
      setMessage({ kind: "ok", text: t("users.created") });
      users.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_USERS_MANAGE, USER_ERROR_KEYS) });
    } finally {
      setCreating(false);
    }
  };

  const handleBanToggle = async () => {
    if (!banTarget) return;
    setBusy(true);
    setMessage(null);
    const next = !banTarget.banned;
    try {
      await setUserBanned(banTarget.id, next);
      setMessage({ kind: "ok", text: next ? t("users.banSuccess") : t("users.unbanSuccess") });
      setBanTarget(null);
      users.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_USERS_MANAGE, USER_ERROR_KEYS) });
      setBanTarget(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<Users className="w-4 h-4 text-primary" />}
        title={t("users.title")}
        desc={t("users.desc")}
        actions={<RefreshButton onClick={users.reload} loading={users.loading} />}
      />

      {createOpen ? (
        <form onSubmit={handleCreate} className="p-4 rounded-card bg-surfaceSubtle border border-line-subtle space-y-3 max-w-md">
          <h3 className="font-semibold text-text-strong text-xs">{t("users.createTitle")}</h3>
          <div>
            <label className={labelClass} htmlFor="new-username">{t("users.field.username")}</label>
            <input
              id="new-username"
              type="text"
              required
              minLength={2}
              maxLength={80}
              value={createForm.username}
              onChange={(e) => setCreateForm((prev) => ({ ...prev, username: e.target.value }))}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass} htmlFor="new-email">{t("users.field.email")}</label>
            <input
              id="new-email"
              type="email"
              value={createForm.email}
              onChange={(e) => setCreateForm((prev) => ({ ...prev, email: e.target.value }))}
              className={inputClass}
            />
            <p className="mt-1 text-[11px] text-text-faint leading-relaxed">{t("users.field.emailHint")}</p>
          </div>
          <div>
            <label className={labelClass} htmlFor="new-password">{t("users.field.password")}</label>
            <input
              id="new-password"
              type="password"
              required
              autoComplete="new-password"
              value={createForm.password}
              onChange={(e) => setCreateForm((prev) => ({ ...prev, password: e.target.value }))}
              className={inputClass}
            />
            <p className="mt-1 text-[11px] text-text-faint leading-relaxed">{t("users.passwordRule")}</p>
          </div>
          <div className="flex items-center gap-2">
            <button type="submit" disabled={creating || createForm.password.length < MIN_PASSWORD} className={primaryButtonClass}>
              {creating ? t("action.creating") : t("users.create")}
            </button>
            <CancelButton
              onClick={() => {
                setCreateOpen(false);
                setMessage(null);
              }}
              label={t("action.cancel")}
            />
          </div>
        </form>
      ) : (
        <button
          type="button"
          onClick={() => {
            setCreateOpen(true);
            setMessage(null);
          }}
          className="px-3 py-1.5 rounded-control bg-primary/15 hover:bg-primary/25 text-primary text-xs font-semibold transition-colors duration-fast ease-soft cursor-pointer inline-flex items-center gap-1.5"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{t("users.create")}</span>
        </button>
      )}

      {users.error ? (
        <ErrorNotice message={users.error} onRetry={users.reload} permissionHint={t("users.needPermission")} />
      ) : null}

      {message && !editing ? <StatusMessage kind={message.kind} text={message.text} /> : null}


      <div className="relative flex items-center max-w-md">
        <Search className="absolute left-3 w-3.5 h-3.5 text-text-faint" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("users.searchPlaceholder")}
          aria-label={t("users.searchPlaceholder")}
          className="w-full pl-9 pr-3 py-1.5 rounded-control bg-surfaceSubtle border border-line text-xs text-text-strong placeholder:text-text-faint focus:border-primary outline-none"
        />
      </div>

      {!users.loading && !users.error ? (
        <p className="text-[11px] text-text-faint font-mono">{t("users.total", { count: visibleUsers.length })}</p>
      ) : null}

      {users.loading && users.data.length === 0 ? <LoadingBlock /> : null}
      {!users.loading && !users.error && visibleUsers.length === 0 ? (
        <EmptyBlock text={query.trim() ? t("users.filterEmpty") : t("state.empty")} />
      ) : null}

      {visibleUsers.length > 0 ? (
        <div className="rounded-card border border-line-subtle bg-surface/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-line-subtle bg-surfaceSubtle text-text-muted font-mono">
                  <th className="py-2.5 px-3 font-medium">{t("users.col.user")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("users.col.status")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("users.col.groups")}</th>
                  <th className="py-2.5 px-3 font-medium text-right">{t("users.col.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {visibleUsers.map((u) => {
                  const isSelf = me?.id === u.id;
                  return (
                    <tr key={u.id} className="hover:bg-surfaceSubtle transition-colors duration-fast ease-soft">
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5">
                          <span className="font-semibold text-text-strong">{u.username}</span>
                          {isSelf ? <Chip tone="neutral">{t("users.you")}</Chip> : null}
                        </div>
                        {/* 邮箱与 ID 挤在同一行：这两个字段没有独立列，凭一行裸值认不出是什么。 */}
                        <div className="text-[10px] text-text-faint font-mono break-all">
                          {u.email ? t("users.inlineEmail", { email: u.email }) + " · " : ""}
                          {t("users.inlineId", { id: u.id })}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <Chip tone={u.banned ? "danger" : "ok"}>{u.banned ? t("users.statusBanned") : t("users.statusActive")}</Chip>
                      </td>
                      <td className="py-2.5 px-3">
                        {(u.groups ?? []).length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {(u.groups ?? []).map((code) => (
                              <Chip key={code}>{code}</Chip>
                            ))}
                          </div>
                        ) : (
                          <span className="text-text-faint font-mono text-[10px]">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => openEditor(u)}
                            className="px-2 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover text-text-body hover:text-text-strong text-[11px] transition-colors duration-fast ease-soft cursor-pointer inline-flex items-center gap-1"
                          >
                            <UserCog className="w-3 h-3" />
                            <span>{t("action.edit")}</span>
                          </button>
                          {/* 封禁自己会被服务端以 cannot_ban_self 拒（封完只能求别人解开），
                              这里提前置灰并说明，而不是让管理员点了才知道。 */}
                          <span title={u.banned ? "" : t("users.selfBanHint")}>
                            <button
                              type="button"
                              disabled={!u.banned && isSelf}
                              onClick={() => {
                                setMessage(null);
                                setBanTarget(u);
                              }}
                              className={`px-2 py-1 rounded-chip text-[11px] transition-colors duration-fast ease-soft inline-flex items-center gap-1 ${
                                u.banned
                                  ? "bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 cursor-pointer"
                                  : "bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                              }`}
                            >
                              {u.banned ? <UserCheck className="w-3 h-3" /> : <Ban className="w-3 h-3" />}
                              <span>{u.banned ? t("users.unban") : t("users.ban")}</span>
                            </button>
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      <Modal
        open={editing != null}
        onClose={closeEditor}
        title={t("users.editTitle")}
        icon={<ShieldCheck className="w-4 h-4 text-primary" />}
      >
        {editing ? (
          <div className="space-y-4 text-xs">
            <div className="p-2.5 rounded-control bg-surfaceSubtle border border-line-subtle font-mono text-[11px] text-text-muted break-all">
              {editing.username} · {editing.id}
            </div>

            {message ? <StatusMessage kind={message.kind} text={message.text} /> : null}

            <div>
              <label className={labelClass} htmlFor="edit-password">{t("users.field.password")}</label>
              <input
                id="edit-password"
                type="password"
                value={form.password}
                autoComplete="new-password"
                onChange={(e) => setForm((prev) => ({ ...prev, password: e.target.value }))}
                placeholder="••••••••••••"
                className={inputClass}
              />
              <p className="mt-1.5 text-[11px] text-text-faint leading-relaxed">{t("users.passwordRule")}</p>
            </div>

            <div>
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className={labelClass + " mb-0"}>{t("users.field.groups")}</span>
                {groups.error ? <span className="text-[10px] font-mono text-rose-300">{t("users.groupsForbiddenHint")}</span> : null}
              </div>
              {groups.error ? (
                // 组清单取不到时不禁用整块编辑：密码仍可改，只是组选择降级为只读展示。
                <p className="p-2 rounded-control bg-rose-500/10 border border-rose-500/30 text-[11px] text-rose-300 leading-relaxed">
                  {groups.error}
                </p>
              ) : null}
              <div className="p-2.5 rounded-control bg-surfaceSubtle border border-line-subtle space-y-1.5 max-h-52 overflow-y-auto">
                {groupList.length === 0 && !groups.loading ? (
                  <span className="text-[11px] text-text-faint font-mono">{t("state.empty")}</span>
                ) : null}
                {groupList.map((group) => (
                  <label
                    key={group.code}
                    className={`flex items-center gap-2 ${groups.error ? "opacity-50" : "cursor-pointer"}`}
                  >
                    <input
                      type="checkbox"
                      disabled={groups.error != null}
                      checked={form.groups.includes(group.code)}
                      onChange={() => toggleGroup(group.code)}
                      className="accent-primary"
                    />
                    <span className="font-mono text-[11px] text-text-strong">{group.code}</span>
                    <span className="text-[10px] text-text-faint">
                      {t("users.groupPermCount", { count: (group.permissions ?? []).length })}
                    </span>
                  </label>
                ))}
              </div>
              <p className="mt-1.5 text-[11px] text-text-faint leading-relaxed">{t("users.groupsHint")}</p>
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <CancelButton onClick={closeEditor} disabled={busy} label={t("action.cancel")} />
              <button type="button" onClick={handleSave} disabled={busy || passwordTooShort} className={primaryButtonClass + " inline-flex items-center gap-1.5"}>
                {busy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />}
                <span>{busy ? t("action.saving") : t("action.save")}</span>
              </button>
            </div>
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={banTarget != null}
        title={banTarget?.banned ? t("users.unban") : t("users.ban")}
        message={
          banTarget?.banned
            ? t("users.unbanConfirm", { username: banTarget?.username ?? "" })
            : t("users.banConfirm", { username: banTarget?.username ?? "" })
        }
        confirmLabel={banTarget?.banned ? t("users.unban") : t("users.ban")}
        busy={busy}
        onClose={() => setBanTarget(null)}
        onConfirm={() => void handleBanToggle()}
      />
    </div>
  );
}

export default function UsersPage() {
  return (
    <RequirePermission code={AUTH_USERS_MANAGE}>
      <UsersPanel />
    </RequirePermission>
  );
}
