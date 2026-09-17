"use client";

// 邀请码治理：台账（含签发人 / 使用情况 / 有效期）、新建、吊销。
//
// 状态是**本地从接口字段推导**的，不新增接口：revoked → 已吊销；expires_at 已过 → 已过期；
// used_count >= max_uses → 已用尽；其余为可用。服务端把 <=0 的 max_uses 归一成 1（上限 1000），
// 所以不存在"不限次数"这种状态，界面也不编一个出来。

import React, { useState } from "react";
import { Plus, Ticket, Trash2 } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";
import { AUTH_INVITES_MANAGE } from "@/lib/permissions";
import { describeCodedError, INVITE_ERROR_KEYS } from "@/lib/errors";
import { formatStamp } from "@/lib/format";
import { createAdminInvite, fetchAdminInvites, revokeAdminInvite, type AdminInvite } from "@/lib/endpoints";
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
const EMPTY_INVITES: AdminInvite[] = [];

function inviteStatus(invite: AdminInvite): "revoked" | "expired" | "exhausted" | "active" {
  if (invite.revoked) return "revoked";
  if (invite.expires_at) {
    const exp = new Date(invite.expires_at);
    if (!Number.isNaN(exp.getTime()) && exp.getTime() <= Date.now()) return "expired";
  }
  if (invite.max_uses > 0 && invite.used_count >= invite.max_uses) return "exhausted";
  return "active";
}

function InvitesPanel() {
  const { t, locale } = useI18n();
  const invites = useResource(fetchAdminInvites, EMPTY_INVITES, AUTH_INVITES_MANAGE);

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ note: "", maxUses: 1, expiresInDays: 0 });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<AdminInvite | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const created = await createAdminInvite({
        note: form.note.trim(),
        max_uses: form.maxUses,
        expires_in_days: form.expiresInDays,
      });
      setForm({ note: "", maxUses: 1, expiresInDays: 0 });
      setCreateOpen(false);
      setMessage({ kind: "ok", text: t("invites.created", { code: created.code }) });
      invites.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_INVITES_MANAGE, INVITE_ERROR_KEYS) });
    } finally {
      setBusy(false);
    }
  };

  const handleRevoke = async () => {
    if (!revokeTarget) return;
    setBusy(true);
    setMessage(null);
    try {
      await revokeAdminInvite(revokeTarget.code);
      setMessage({ kind: "ok", text: t("invites.revoked", { code: revokeTarget.code }) });
      setRevokeTarget(null);
      invites.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_INVITES_MANAGE, INVITE_ERROR_KEYS) });
      setRevokeTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const statusTone = { active: "ok", revoked: "danger", exhausted: "warn", expired: "warn" } as const;

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<Ticket className="w-4 h-4 text-primary" />}
        title={t("invites.title")}
        desc={t("invites.desc")}
        actions={
          <>
            <button
              type="button"
              onClick={() => {
                setCreateOpen(true);
                setMessage(null);
              }}
              className={primaryButtonClass + " inline-flex items-center gap-1.5"}
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{t("invites.create")}</span>
            </button>
            <RefreshButton onClick={invites.reload} loading={invites.loading} />
          </>
        }
      />

      {createOpen ? (
        <form onSubmit={handleCreate} className="p-4 rounded-card bg-surfaceSubtle border border-line-subtle space-y-3 max-w-md">
          <h3 className="font-semibold text-text-strong text-xs">{t("invites.createTitle")}</h3>
          <div>
            <label className={labelClass} htmlFor="invite-note">{t("invites.field.note")}</label>
            <input
              id="invite-note"
              type="text"
              value={form.note}
              maxLength={200}
              onChange={(e) => setForm((prev) => ({ ...prev, note: e.target.value }))}
              className={inputClass}
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className={labelClass} htmlFor="invite-max-uses">{t("invites.field.maxUses")}</label>
              <input
                id="invite-max-uses"
                type="number"
                min={1}
                max={1000}
                value={form.maxUses}
                onChange={(e) => setForm((prev) => ({ ...prev, maxUses: Number(e.target.value) || 1 }))}
                className={inputClass + " font-mono"}
              />
            </div>
            <div>
              <label className={labelClass} htmlFor="invite-expires">{t("invites.field.expiresInDays")}</label>
              <input
                id="invite-expires"
                type="number"
                min={0}
                value={form.expiresInDays}
                onChange={(e) => setForm((prev) => ({ ...prev, expiresInDays: Number(e.target.value) || 0 }))}
                className={inputClass + " font-mono"}
              />
            </div>
          </div>
          <p className="text-[11px] text-text-faint leading-relaxed">{t("invites.fieldHint")}</p>
          <div className="flex items-center gap-2">
            <button type="submit" disabled={busy} className={primaryButtonClass}>
              {busy ? t("action.creating") : t("invites.create")}
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
      ) : null}

      {invites.error ? (
        <ErrorNotice message={invites.error} onRetry={invites.reload} permissionHint={t("invites.needPermission")} />
      ) : null}
      {message ? <StatusMessage kind={message.kind} text={message.text} /> : null}

      {invites.loading && invites.data.length === 0 ? <LoadingBlock /> : null}
      {!invites.loading && !invites.error && invites.data.length === 0 ? <EmptyBlock /> : null}

      {invites.data.length > 0 ? (
        <div className="rounded-card border border-line-subtle bg-surface/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-line-subtle bg-surfaceSubtle text-text-muted font-mono">
                  <th className="py-2.5 px-3 font-medium">{t("invites.col.code")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("invites.col.creator")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("invites.col.usage")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("invites.col.status")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("invites.col.expires")}</th>
                  <th className="py-2.5 px-3 font-medium text-right">{t("invites.col.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {invites.data.map((invite) => {
                  const status = inviteStatus(invite);
                  return (
                    <tr key={invite.code} className="hover:bg-surfaceSubtle transition-colors duration-fast ease-soft">
                      <td className="py-2.5 px-3">
                        <div className="font-mono text-[11px] text-text-strong">{invite.code}</div>
                        {invite.note ? <div className="text-[10px] text-text-faint">{invite.note}</div> : null}
                        <div className="text-[10px] text-text-faint font-mono">
                          {t("invites.createdAt", { stamp: formatStamp(invite.created_at, locale) })}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-text-body font-mono text-[11px]">{invite.creator || invite.created_by || "—"}</td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-text-body">
                        {t("invites.usage", { used: invite.used_count, max: invite.max_uses })}
                      </td>
                      <td className="py-2.5 px-3">
                        <Chip tone={statusTone[status]}>{t("invites.status." + status)}</Chip>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-text-muted">
                        {invite.expires_at ? formatStamp(invite.expires_at, locale) : t("invites.noExpiry")}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          type="button"
                          disabled={invite.revoked}
                          onClick={() => {
                            setMessage(null);
                            setRevokeTarget(invite);
                          }}
                          className="px-2 py-1 rounded-chip bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 text-[11px] transition-colors duration-fast ease-soft disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer inline-flex items-center gap-1"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>{t("invites.revoke")}</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      <ConfirmDialog
        open={revokeTarget != null}
        title={t("invites.revokeTitle")}
        message={t("invites.revokeConfirm", { code: revokeTarget?.code ?? "" })}
        confirmLabel={t("invites.revoke")}
        busy={busy}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => void handleRevoke()}
      />
    </div>
  );
}

export default function InvitesPage() {
  return (
    <RequirePermission code={AUTH_INVITES_MANAGE}>
      <InvitesPanel />
    </RequirePermission>
  );
}
