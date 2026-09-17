"use client";

// OAuth 客户端治理：列表（系统应用 / 第三方应用两组）、创建（一次性明文密钥）、轮换密钥、
// 删除、停用/启用、核验/取消核验。
//
// 边界：client_secret 只在创建与轮换的响应里出现一次（库里只有 bcrypt 哈希），
// 所以界面拿到后必须立刻让用户保存；"再看一眼密钥"这种入口不存在，也不该伪造。
//
// 分组依据是**归属**（owner_user_id 为空 = 平台登记的系统应用），不是"是否种子"：
// 种子名单只说明服务端会复活这几行、删不掉，与"谁是系统应用"无关。判定与依据写在
// lib/endpoints.ts 的 isSystemClient 上，这里不再自己猜。
// 系统应用只能在这里维护——开发者中心按 owner_user_id 过滤，看不见也管不着它们。
//
// 核验：管理员核实第三方应用的身份后置 verified（PUT /api/admin/oauth/clients/{id}），
// 未核验的第三方应用在同意页会多显示一条提示，所以这一步走二次确认。系统应用免同意、
// 展示上恒为已核验，不给它核验开关——不是"藏起当前状态"，而是这个动作对系统应用没有意义。

import React, { useState } from "react";
import { KeyRound, Plus } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";
import { AUTH_OAUTH_MANAGE } from "@/lib/permissions";
import { describeCodedError, OAUTH_ERROR_KEYS } from "@/lib/errors";
import {
  createOAuthClient,
  deleteOAuthClient,
  fetchOAuthClients,
  isSystemClient,
  OAUTH_CLIENT_ID_RE,
  OAUTH_SCOPES,
  rotateOAuthClientSecret,
  updateOAuthClient,
  type OAuthClient,
  type OAuthClientSecret,
} from "@/lib/endpoints";
import { RequirePermission } from "@/components/PermissionGate";
import { OAuthClientGroup, type OAuthClientActions } from "@/components/OAuthClientGroup";
import { CancelButton, ConfirmDialog, Modal } from "@/components/ui/Modal";
import {
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
const EMPTY_CLIENTS: OAuthClient[] = [];

type ConfirmKind = "rotate" | "delete" | "disable" | "verify" | "unverify";

function OAuthClientsPanel() {
  const { t } = useI18n();
  const clients = useResource(fetchOAuthClients, EMPTY_CLIENTS, AUTH_OAUTH_MANAGE);

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ clientId: "", name: "", redirectUris: "", scopes: ["openid"] as string[], trusted: false });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [confirmTarget, setConfirmTarget] = useState<{ client: OAuthClient; kind: ConfirmKind } | null>(null);
  const [secret, setSecret] = useState<OAuthClientSecret | null>(null);
  const [copied, setCopied] = useState(false);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const clientId = form.clientId.trim();
    if (!OAUTH_CLIENT_ID_RE.test(clientId)) {
      setMessage({ kind: "err", text: t("oauth.clientIdInvalid") });
      return;
    }
    const redirectUris = form.redirectUris
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    if (redirectUris.length === 0) {
      setMessage({ kind: "err", text: t("oauth.redirectUrisRequired") });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      // 只提交形状列：归属由服务端保持为空（管理台创建的就是系统应用），界面也没有归属选项。
      const created = await createOAuthClient({
        client_id: clientId,
        name: form.name.trim() || clientId,
        redirect_uris: redirectUris,
        scopes: form.scopes,
        trusted: form.trusted,
      });
      setCreateOpen(false);
      setForm({ clientId: "", name: "", redirectUris: "", scopes: ["openid"], trusted: false });
      setCopied(false);
      setSecret(created);
      clients.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_OAUTH_MANAGE, OAUTH_ERROR_KEYS) });
    } finally {
      setBusy(false);
    }
  };

  const runConfirm = async () => {
    if (!confirmTarget) return;
    const { client, kind } = confirmTarget;
    setBusy(true);
    setMessage(null);
    try {
      if (kind === "rotate") {
        const rotated = await rotateOAuthClientSecret(client.client_id);
        setCopied(false);
        setSecret(rotated);
        setMessage({ kind: "ok", text: t("oauth.rotated", { name: client.client_id }) });
      } else if (kind === "delete") {
        await deleteOAuthClient(client.client_id);
        setMessage({ kind: "ok", text: t("oauth.deleted", { name: client.client_id }) });
      } else if (kind === "verify") {
        // 管理面 PUT 是补丁语义：只提交 verified 这一个键，别的字段一律不碰。
        await updateOAuthClient(client.client_id, { verified: true });
        setMessage({ kind: "ok", text: t("oauth.verified", { name: client.client_id }) });
      } else if (kind === "unverify") {
        await updateOAuthClient(client.client_id, { verified: false });
        setMessage({ kind: "ok", text: t("oauth.unverified", { name: client.client_id }) });
      } else {
        await updateOAuthClient(client.client_id, { disabled: true });
        setMessage({ kind: "ok", text: t("oauth.disabled", { name: client.client_id }) });
      }
      setConfirmTarget(null);
      clients.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_OAUTH_MANAGE, OAUTH_ERROR_KEYS) });
      setConfirmTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const handleEnable = async (client: OAuthClient) => {
    setBusy(true);
    setMessage(null);
    try {
      await updateOAuthClient(client.client_id, { disabled: false });
      setMessage({ kind: "ok", text: t("oauth.enabled", { name: client.client_id }) });
      clients.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_OAUTH_MANAGE, OAUTH_ERROR_KEYS) });
    } finally {
      setBusy(false);
    }
  };

  const copySecret = async () => {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret.client_secret);
      setCopied(true);
    } catch {
      // 剪贴板不可用（非安全上下文/无权限）时不谎报成功：让用户手动选中复制。
      setCopied(false);
    }
  };

  const confirmText = () => {
    if (!confirmTarget) return "";
    const name = confirmTarget.client.client_id;
    if (confirmTarget.kind === "rotate") return t("oauth.rotateConfirm", { name });
    if (confirmTarget.kind === "delete") return t("oauth.deleteConfirm", { name });
    if (confirmTarget.kind === "disable") return t("oauth.disableConfirm", { name });
    if (confirmTarget.kind === "verify") return t("oauth.verifyConfirm", { name });
    return t("oauth.unverifyConfirm", { name });
  };

  const confirmTitle = () => {
    if (!confirmTarget) return "";
    if (confirmTarget.kind === "rotate") return t("oauth.rotateTitle");
    if (confirmTarget.kind === "delete") return t("oauth.deleteTitle");
    if (confirmTarget.kind === "disable") return t("oauth.disableTitle");
    if (confirmTarget.kind === "verify") return t("oauth.verifyTitle");
    return t("oauth.unverifyTitle");
  };

  const confirmLabel = () => {
    if (!confirmTarget) return "";
    if (confirmTarget.kind === "rotate") return t("oauth.rotate");
    if (confirmTarget.kind === "delete") return t("action.delete");
    if (confirmTarget.kind === "disable") return t("oauth.disable");
    if (confirmTarget.kind === "verify") return t("oauth.verify");
    return t("oauth.unverify");
  };

  const actions: OAuthClientActions = {
    onRotate: (client) => {
      setCopied(false);
      setConfirmTarget({ client, kind: "rotate" });
    },
    onToggleDisabled: (client) => {
      // 停用会让令牌立即失效，所以过二次确认；启用是恢复动作，直接放行。
      if (client.disabled) {
        void handleEnable(client);
        return;
      }
      setMessage(null);
      setConfirmTarget({ client, kind: "disable" });
    },
    onToggleVerified: (client) => {
      // 核验/取消核验都改同意页对外的表达，所以两个方向都过二次确认。
      setMessage(null);
      setConfirmTarget({ client, kind: client.verified ? "unverify" : "verify" });
    },
    onDelete: (client) => {
      setMessage(null);
      setConfirmTarget({ client, kind: "delete" });
    },
  };

  // 两组共用同一份动作：分组的差别只在"这是什么应用"，不在"能做什么"。
  const systemClients = clients.data.filter(isSystemClient);
  const thirdPartyClients = clients.data.filter((client) => !isSystemClient(client));

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<KeyRound className="w-4 h-4 text-primary" />}
        title={t("oauth.title")}
        desc={t("oauth.desc")}
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
              <span>{t("oauth.create")}</span>
            </button>
            <RefreshButton onClick={clients.reload} loading={clients.loading} />
          </>
        }
      />

      {message ? <StatusMessage kind={message.kind} text={message.text} /> : null}

      {createOpen ? (
        <form onSubmit={handleCreate} className="p-4 rounded-card bg-surfaceSubtle border border-line-subtle space-y-3 max-w-xl">
          <h3 className="font-semibold text-text-strong text-xs">{t("oauth.createTitle")}</h3>
          <p className="text-[11px] text-text-muted leading-relaxed">{t("oauth.createSystemNote")}</p>
          <div>
            <label className={labelClass} htmlFor="oauth-client-id">{t("oauth.field.clientId")}</label>
            <input
              id="oauth-client-id"
              type="text"
              required
              value={form.clientId}
              onChange={(e) => setForm((prev) => ({ ...prev, clientId: e.target.value }))}
              className={inputClass + " font-mono"}
            />
            <p className="mt-1 text-[11px] text-text-faint leading-relaxed">{t("oauth.field.clientIdHint")}</p>
          </div>
          <div>
            <label className={labelClass} htmlFor="oauth-client-name">{t("oauth.field.name")}</label>
            <input
              id="oauth-client-name"
              type="text"
              value={form.name}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass} htmlFor="oauth-redirects">{t("oauth.field.redirectUris")}</label>
            <textarea
              id="oauth-redirects"
              rows={3}
              value={form.redirectUris}
              onChange={(e) => setForm((prev) => ({ ...prev, redirectUris: e.target.value }))}
              className={inputClass + " font-mono resize-y"}
            />
            <p className="mt-1 text-[11px] text-text-faint leading-relaxed">{t("oauth.field.redirectUrisHint")}</p>
          </div>
          <div>
            <span className={labelClass + " mb-0"}>{t("oauth.field.scopes")}</span>
            <div className="flex flex-wrap gap-3 mt-1">
              {OAUTH_SCOPES.map((scope) => (
                <label key={scope} className="inline-flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.scopes.includes(scope)}
                    onChange={() =>
                      setForm((prev) => ({
                        ...prev,
                        scopes: prev.scopes.includes(scope)
                          ? prev.scopes.filter((s) => s !== scope)
                          : [...prev.scopes, scope],
                      }))
                    }
                    className="accent-primary"
                  />
                  <span className="font-mono text-[11px] text-text-strong">{scope}</span>
                </label>
              ))}
            </div>
            <p className="mt-1 text-[11px] text-text-faint leading-relaxed">{t("oauth.field.scopesHint")}</p>
          </div>
          <label className="inline-flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={form.trusted}
              onChange={(e) => setForm((prev) => ({ ...prev, trusted: e.target.checked }))}
              className="accent-primary"
            />
            <span className="text-[11px] text-text-body">{t("oauth.field.trusted")}</span>
          </label>
          <p className="text-[11px] text-amber-400/80 leading-relaxed">{t("oauth.field.trustedHint")}</p>
          <div className="flex items-center gap-2">
            <button type="submit" disabled={busy} className={primaryButtonClass}>
              {busy ? t("action.creating") : t("oauth.create")}
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

      {clients.error ? (
        <ErrorNotice message={clients.error} onRetry={clients.reload} permissionHint={t("oauth.needPermission")} />
      ) : null}

      {clients.loading && clients.data.length === 0 ? (
        <LoadingBlock />
      ) : (
        <div className="space-y-5">
          <OAuthClientGroup
            title={t("oauth.group.system")}
            desc={t("oauth.group.systemDesc")}
            emptyText={t("oauth.group.systemEmpty")}
            clients={systemClients}
            actions={actions}
          />
          <OAuthClientGroup
            title={t("oauth.group.thirdParty")}
            desc={t("oauth.group.thirdPartyDesc")}
            emptyText={t("oauth.group.thirdPartyEmpty")}
            clients={thirdPartyClients}
            actions={actions}
          />
        </div>
      )}

      <ConfirmDialog
        open={confirmTarget != null}
        title={confirmTitle()}
        message={confirmText()}
        confirmLabel={confirmLabel()}
        // 核验是"确认无误"的放行动作，不该用破坏性的红色按钮；取消核验与其余动作都是收回权限。
        danger={confirmTarget?.kind !== "verify"}
        busy={busy}
        onClose={() => setConfirmTarget(null)}
        onConfirm={() => void runConfirm()}
      />

      <Modal
        open={secret != null}
        onClose={() => setSecret(null)}
        title={t("oauth.secretTitle")}
        icon={<KeyRound className="w-4 h-4 text-amber-400" />}
      >
        <div className="space-y-3 text-xs">
          <p className="p-2.5 rounded-control bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-200 leading-relaxed">
            {t("oauth.secretWarn")}
          </p>
          <div>
            <span className={labelClass + " mb-0"}>{t("oauth.secretClientId")}</span>
            <div className="font-mono text-[11px] text-text-strong break-all">{secret?.client.client_id}</div>
          </div>
          <div>
            <span className={labelClass + " mb-0"}>{t("oauth.secretLabel")}</span>
            <div className="p-2.5 rounded-control bg-surfaceSubtle border border-line font-mono text-[11px] text-text-strong break-all select-all">
              {secret?.client_secret}
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={() => void copySecret()} className="px-3 py-1.5 rounded-control bg-surfaceSubtle hover:bg-surfaceHover border border-line text-text-body text-xs transition-colors duration-fast ease-soft cursor-pointer">
              {copied ? t("action.copied") : t("action.copy")}
            </button>
            <button type="button" onClick={() => setSecret(null)} className={primaryButtonClass}>
              {t("oauth.secretDone")}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

export default function OAuthClientsPage() {
  return (
    <RequirePermission code={AUTH_OAUTH_MANAGE}>
      <OAuthClientsPanel />
    </RequirePermission>
  );
}
