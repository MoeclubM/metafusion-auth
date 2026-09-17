"use client";

// 权限组：列表 + 新建 / 编辑 / 删除，以及权限码说明。
//
// 边界（与账号服务同口径）：账号服务只负责**存组、存权限码、算出某人的权限集合**，
// 不解释权限码的含义；本页也只把接口给的 service 前缀原样透出，由界面标明
// "每个子系统各解释自己那些码"。系统组可改权限但不可删（服务端 system_group_immutable）。

import React, { useMemo, useState } from "react";
import { Ban, Plus, Save, Shapes, Trash2, X } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";
import { AUTH_GROUPS_MANAGE } from "@/lib/permissions";
import { describeCodedError, GROUP_ERROR_KEYS } from "@/lib/errors";
import { pickLocalizedName, sortGroups } from "@/lib/format";
import { locales } from "@/i18n/routing";
import {
  createAdminGroup,
  deleteAdminGroup,
  fetchAdminGroups,
  fetchAdminPermissions,
  GROUP_CODE_RE,
  PERMISSION_CODE_RE,
  updateAdminGroup,
  type AdminGroup,
  type AdminPermissionCode,
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

// 模块级常量：useResource 的 initial 必须是稳定引用。
const EMPTY_GROUPS: AdminGroup[] = [];
const EMPTY_PERMISSIONS: AdminPermissionCode[] = [];

interface GroupDraft {
  code: string;
  names: Record<string, string>;
  descriptions: Record<string, string>;
  permissions: string[];
  sort_order: number;
}

const emptyDraft = (): GroupDraft => ({
  code: "",
  names: { "zh-CN": "", "en-US": "", "zh-TW": "", "ja-JP": "" },
  descriptions: {},
  permissions: [],
  sort_order: 0,
});

/** 权限码分组：前缀优先取接口给的 service，缺了退回码的第一段；* 单独成组。 */
function permissionPrefix(code: string, catalog: AdminPermissionCode[]): string {
  if (code === "*") return "*";
  const service = catalog.find((p) => p.code === code)?.service;
  if (service) return service;
  return code.split(".")[0] || code;
}

function groupedPermissions(catalog: AdminPermissionCode[]): { prefix: string; items: AdminPermissionCode[] }[] {
  const order: string[] = [];
  const byPrefix = new Map<string, AdminPermissionCode[]>();
  for (const item of catalog) {
    const prefix = permissionPrefix(item.code, catalog);
    const bucket = byPrefix.get(prefix);
    if (bucket) bucket.push(item);
    else {
      byPrefix.set(prefix, [item]);
      order.push(prefix);
    }
  }
  return order.map((prefix) => ({ prefix, items: byPrefix.get(prefix) ?? [] }));
}

function MultilingualFields({
  label,
  value,
  onChange,
  required,
  rows = 1,
}: {
  label: string;
  value: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
  required?: boolean;
  rows?: number;
}) {
  const { t } = useI18n();
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className={labelClass + " mb-0"}>
          {label}
          {required ? <span className="text-rose-400 ml-1">*</span> : null}
        </span>
        {required ? <span className="text-[10px] text-text-faint font-mono">{t("groups.allLocalesRequired")}</span> : null}
      </div>
      {locales.map((code) => (
        <div key={code} className="flex items-start gap-2">
          <span className="px-2 py-1.5 rounded-chip bg-surfaceSubtle text-text-body text-[10px] font-mono shrink-0 w-[62px] text-center">
            {code}
          </span>
          {rows > 1 ? (
            <textarea
              rows={rows}
              value={value[code] ?? ""}
              onChange={(e) => onChange({ ...value, [code]: e.target.value })}
              className={inputClass + " resize-y"}
            />
          ) : (
            <input
              type="text"
              value={value[code] ?? ""}
              onChange={(e) => onChange({ ...value, [code]: e.target.value })}
              className={inputClass}
            />
          )}
        </div>
      ))}
    </div>
  );
}

function GroupsPanel() {
  const { t, tr, locale } = useI18n();
  const groups = useResource(fetchAdminGroups, EMPTY_GROUPS, AUTH_GROUPS_MANAGE);
  const catalog = useResource(fetchAdminPermissions, EMPTY_PERMISSIONS, AUTH_GROUPS_MANAGE);

  const [editingCode, setEditingCode] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState<GroupDraft>(emptyDraft());
  const [customCode, setCustomCode] = useState("");
  const [customError, setCustomError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AdminGroup | null>(null);

  const groupList = useMemo(() => sortGroups(groups.data), [groups.data]);
  const permissions = useMemo(() => groupedPermissions(catalog.data), [catalog.data]);
  const modalOpen = creating || editingCode != null;

  const openCreate = () => {
    setDraft(emptyDraft());
    setCreating(true);
    setEditingCode(null);
    setCustomError(null);
    setCustomCode("");
    setMessage(null);
  };

  const openEdit = (group: AdminGroup) => {
    setDraft({
      code: group.code,
      names: { ...(group.names ?? {}) },
      descriptions: { ...(group.descriptions ?? {}) },
      permissions: [...(group.permissions ?? [])],
      sort_order: group.sort_order ?? 0,
    });
    setCreating(false);
    setEditingCode(group.code);
    setCustomError(null);
    setCustomCode("");
    setMessage(null);
  };

  const closeModal = () => {
    setCreating(false);
    setEditingCode(null);
    setMessage(null);
  };

  const togglePermission = (code: string) => {
    setDraft((prev) => ({
      ...prev,
      permissions: prev.permissions.includes(code)
        ? prev.permissions.filter((c) => c !== code)
        : [...prev.permissions, code],
    }));
  };

  const addCustom = () => {
    const code = customCode.trim();
    if (!code) return;
    if (!PERMISSION_CODE_RE.test(code)) {
      setCustomError(t("groups.permInvalid"));
      return;
    }
    setCustomError(null);
    setCustomCode("");
    setDraft((prev) => (prev.permissions.includes(code) ? prev : { ...prev, permissions: [...prev.permissions, code] }));
  };

  const save = async () => {
    const code = draft.code.trim();
    if (creating && !GROUP_CODE_RE.test(code)) {
      setMessage({ kind: "err", text: t("groups.codeInvalid") });
      return;
    }
    if (locales.some((l) => (draft.names[l] ?? "").trim() === "")) {
      setMessage({ kind: "err", text: t("groups.allLocalesRequired") });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const payload: AdminGroup = {
        code,
        names: draft.names,
        descriptions: draft.descriptions,
        permissions: draft.permissions,
        sort_order: draft.sort_order,
      };
      if (creating) await createAdminGroup(payload);
      else await updateAdminGroup(code, payload);
      setMessage({ kind: "ok", text: creating ? t("groups.created") : t("groups.saved") });
      closeModal();
      groups.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_GROUPS_MANAGE, GROUP_ERROR_KEYS) });
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setBusy(true);
    setMessage(null);
    try {
      await deleteAdminGroup(deleteTarget.code);
      setMessage({ kind: "ok", text: t("groups.deleted", { code: deleteTarget.code }) });
      setDeleteTarget(null);
      groups.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_GROUPS_MANAGE, GROUP_ERROR_KEYS) });
      setDeleteTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const selectedCustom = draft.permissions.filter(
    (code) => !catalog.data.some((item) => item.code === code)
  );

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<Shapes className="w-4 h-4 text-primary" />}
        title={t("groups.title")}
        desc={t("groups.desc")}
        actions={
          <>
            <button type="button" onClick={openCreate} className={primaryButtonClass + " inline-flex items-center gap-1.5"}>
              <Plus className="w-3.5 h-3.5" />
              <span>{t("groups.create")}</span>
            </button>
            <RefreshButton onClick={groups.reload} loading={groups.loading} />
          </>
        }
      />

      {groups.error ? (
        <ErrorNotice message={groups.error} onRetry={groups.reload} permissionHint={t("groups.needPermission")} />
      ) : null}
      {message && !modalOpen ? <StatusMessage kind={message.kind} text={message.text} /> : null}

      {groups.loading && groups.data.length === 0 ? <LoadingBlock /> : null}
      {!groups.loading && !groups.error && groupList.length === 0 ? <EmptyBlock /> : null}

      {groupList.length > 0 ? (
        <div className="rounded-card border border-line-subtle bg-surface/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-line-subtle bg-surfaceSubtle text-text-muted font-mono">
                  <th className="py-2.5 px-3 font-medium">{t("groups.col.code")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("groups.col.name")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("groups.col.perms")}</th>
                  <th className="py-2.5 px-3 font-medium text-right">{t("groups.col.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {groupList.map((group) => (
                  <tr key={group.code} className="hover:bg-surfaceSubtle transition-colors duration-fast ease-soft">
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[11px] text-text-strong">{group.code}</span>
                        {group.is_system ? (
                          <Chip tone="warn">
                            <Ban className="w-2.5 h-2.5 mr-0.5" />
                            {t("groups.system")}
                          </Chip>
                        ) : null}
                      </div>
                      <div className="text-[10px] text-text-faint font-mono">{t("groups.sortLabel", { order: group.sort_order ?? 0 })}</div>
                    </td>
                    <td className="py-2.5 px-3 text-text-body">{pickLocalizedName(group.names, locale, group.code)}</td>
                    <td className="py-2.5 px-3">
                      <div className="flex flex-wrap gap-1">
                        {(group.permissions ?? []).length === 0 ? (
                          <span className="text-text-faint font-mono text-[10px]">—</span>
                        ) : (
                          (group.permissions ?? []).map((code) => <Chip key={code}>{code}</Chip>)
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => openEdit(group)}
                          className="px-2 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover text-text-body text-[11px] transition-colors duration-fast ease-soft cursor-pointer"
                        >
                          {t("action.edit")}
                        </button>
                        <button
                          type="button"
                          disabled={group.is_system}
                          title={group.is_system ? t("groups.systemLocked") : ""}
                          onClick={() => {
                            setMessage(null);
                            setDeleteTarget(group);
                          }}
                          className="px-2 py-1 rounded-chip bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 text-[11px] transition-colors duration-fast ease-soft disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer inline-flex items-center gap-1"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>{t("action.delete")}</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      <div className="p-4 rounded-card bg-surfaceSubtle border border-line-subtle space-y-3">
        <h3 className="text-sm font-semibold text-text-strong">{t("groups.permsTitle")}</h3>
        <p className="text-[11px] text-text-muted leading-relaxed">{t("groups.permsDesc")}</p>
        {catalog.error ? (
          <ErrorNotice message={catalog.error} onRetry={catalog.reload} permissionHint={t("groups.needPermission")} />
        ) : null}
        {catalog.loading && catalog.data.length === 0 ? <LoadingBlock /> : null}
        {permissions.map(({ prefix, items }) => (
          <div key={prefix} className="space-y-1.5">
            <div className="flex items-center gap-2">
              <Chip>{prefix === "*" ? "*" : prefix + ".*"}</Chip>
              <span className="text-[11px] text-text-muted">
                {tr("groups.service." + prefix, prefix)} · {t("groups.permCount", { count: items.length })}
              </span>
            </div>
            <ul className="space-y-1">
              {items.map((item) => (
                <li key={item.code} className="flex flex-wrap items-baseline gap-2 pl-2">
                  <code className="text-[11px] font-mono text-text-strong">{item.code}</code>
                  <span className="text-[11px] text-text-body">{pickLocalizedName(item.names, locale, "")}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={creating ? t("groups.createTitle") : t("groups.editTitle")}
        icon={<Shapes className="w-4 h-4 text-primary" />}
        maxWidth="max-w-2xl"
      >
        <div className="space-y-4 text-xs">
          {message ? <StatusMessage kind={message.kind} text={message.text} /> : null}

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className={labelClass} htmlFor="group-code">{t("groups.field.code")}</label>
              <input
                id="group-code"
                type="text"
                value={draft.code}
                disabled={!creating}
                onChange={(e) => setDraft((prev) => ({ ...prev, code: e.target.value }))}
                className={inputClass + " font-mono disabled:opacity-60"}
              />
              <p className="mt-1 text-[11px] text-text-faint leading-relaxed">
                {creating ? t("groups.field.codeHint") : t("groups.field.codeImmutable")}
              </p>
            </div>
            <div>
              <label className={labelClass} htmlFor="group-sort">{t("groups.field.sort")}</label>
              <input
                id="group-sort"
                type="number"
                value={draft.sort_order}
                onChange={(e) => setDraft((prev) => ({ ...prev, sort_order: Number(e.target.value) || 0 }))}
                className={inputClass + " font-mono"}
              />
            </div>
          </div>

          <MultilingualFields label={t("groups.field.names")} value={draft.names} onChange={(names) => setDraft((prev) => ({ ...prev, names }))} required />
          <MultilingualFields
            label={t("groups.field.descriptions")}
            value={draft.descriptions}
            onChange={(descriptions) => setDraft((prev) => ({ ...prev, descriptions }))}
            rows={2}
          />

          <div className="space-y-2">
            <span className={labelClass + " mb-0"}>{t("groups.field.permissions")}</span>
            <div className="p-2.5 rounded-control bg-surfaceSubtle border border-line-subtle space-y-2 max-h-64 overflow-y-auto">
              {permissions.length === 0 ? (
                <span className="text-[11px] text-text-faint font-mono">{t("groups.permsUnavailable")}</span>
              ) : null}
              {permissions.map(({ prefix, items }) => (
                <div key={prefix} className="space-y-1">
                  <div className="text-[10px] font-mono text-text-faint">{prefix === "*" ? "*" : prefix + ".*"}</div>
                  {items.map((item) => (
                    <label key={item.code} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={draft.permissions.includes(item.code)}
                        onChange={() => togglePermission(item.code)}
                        className="accent-primary"
                      />
                      <span className="font-mono text-[11px] text-text-strong">{item.code}</span>
                      <span className="text-[10px] text-text-faint">{pickLocalizedName(item.names, locale, "")}</span>
                    </label>
                  ))}
                </div>
              ))}
            </div>

            {selectedCustom.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {selectedCustom.map((code) => (
                  <span key={code} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-chip bg-sky-500/15 border border-sky-500/30 text-sky-300 text-[10px] font-mono">
                    {code}
                    <button type="button" onClick={() => togglePermission(code)} className="hover:text-rose-300 cursor-pointer" aria-label={t("action.remove")}>
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            ) : null}

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addCustom();
                  }
                }}
                placeholder={t("groups.permCustomPlaceholder")}
                aria-label={t("groups.permCustomPlaceholder")}
                className={inputClass + " font-mono sm:max-w-xs"}
              />
              <button type="button" onClick={addCustom} className="px-2.5 py-1.5 rounded-control bg-surfaceSubtle hover:bg-surfaceHover border border-line text-[11px] text-text-body transition-colors duration-fast ease-soft cursor-pointer">
                {t("groups.permAdd")}
              </button>
            </div>
            <p className="text-[10px] text-text-faint leading-relaxed">{customError ?? t("groups.permCustomHint")}</p>
          </div>

          <div className="flex justify-end gap-2 pt-1">
            <CancelButton onClick={closeModal} disabled={busy} label={t("action.cancel")} />
            <button type="button" onClick={() => void save()} disabled={busy} className={primaryButtonClass + " inline-flex items-center gap-1.5"}>
              <Save className="w-3.5 h-3.5" />
              <span>{busy ? t("action.saving") : t("action.save")}</span>
            </button>
          </div>
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteTarget != null}
        title={t("groups.deleteConfirmTitle")}
        message={t("groups.deleteConfirm", { code: deleteTarget?.code ?? "" })}
        confirmLabel={t("action.delete")}
        busy={busy}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => void handleDelete()}
      />
    </div>
  );
}

export default function GroupsPage() {
  return (
    <RequirePermission code={AUTH_GROUPS_MANAGE}>
      <GroupsPanel />
    </RequirePermission>
  );
}
