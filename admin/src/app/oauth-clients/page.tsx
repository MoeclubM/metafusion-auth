"use client";

// OAuth 客户端治理：列表、创建（一次性明文密钥）、轮换密钥、删除、停用/启用。
//
// 边界：client_secret 只在创建与轮换的响应里出现一次（库里只有 bcrypt 哈希），
// 所以界面拿到后必须立刻让用户保存；"再看一眼密钥"这种入口不存在，也不该伪造。
// 第一方种子客户端由服务端保护（seeded_client_immutable），删除按钮提前置灰并说明。

import React, { useState } from "react";
import { KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";
import { AUTH_OAUTH_MANAGE } from "@/lib/permissions";
import { describeCodedError, OAUTH_ERROR_KEYS } from "@/lib/errors";
import { formatStamp } from "@/lib/format";
import {
  createOAuthClient,
  deleteOAuthClient,
  fetchOAuthClients,
  OAUTH_CLIENT_ID_RE,
  OAUTH_SCOPES,
  rotateOAuthClientSecret,
  updateOAuthClient,
  type OAuthClient,
  type OAuthClientSecret,
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
const EMPTY_CLIENTS: OAuthClient[] = [];

/** 第一方种子客户端：这些 client_id 由账号服务在 Init 里写入，删不掉。 */
const SEEDED_CLIENTS = new Set(["metafusion-catalog", "metafusion-forum", "metafusion-resources"]);

type ConfirmKind = "rotate" | "delete" | "disable";

function OAuthClientsPanel() {
  const { t, locale } = useI18n();
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
    return t("oauth.disableConfirm", { name });
  };

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

      {clients.loading && clients.data.length === 0 ? <LoadingBlock /> : null}
      {!clients.loading && !clients.error && clients.data.length === 0 ? <EmptyBlock /> : null}

      {clients.data.length > 0 ? (
        <div className="rounded-card border border-line-subtle bg-surface/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-line-subtle bg-surfaceSubtle text-text-muted font-mono">
                  <th className="py-2.5 px-3 font-medium">{t("oauth.col.client")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("oauth.col.scopes")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("oauth.col.flags")}</th>
                  <th className="py-2.5 px-3 font-medium text-right">{t("oauth.col.actions")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {clients.data.map((client) => {
                  const seeded = SEEDED_CLIENTS.has(client.client_id);
                  return (
                    <tr key={client.client_id} className="hover:bg-surfaceSubtle transition-colors duration-fast ease-soft">
                      <td className="py-2.5 px-3">
                        <div className="font-mono text-[11px] text-text-strong">{client.client_id}</div>
                        <div className="text-[10px] text-text-muted">{client.name}</div>
                        <div className="text-[10px] text-text-faint font-mono break-all">
                          {client.redirect_uris.join(", ") || t("oauth.noRedirectUris")}
                        </div>
                        <div className="text-[10px] text-text-faint font-mono">
                          {t("oauth.createdAt", { stamp: formatStamp(client.created_at, locale) })}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex flex-wrap gap-1">
                          {client.scopes.length === 0 ? (
                            <span className="text-text-faint font-mono text-[10px]">—</span>
                          ) : (
                            client.scopes.map((scope) => <Chip key={scope}>{scope}</Chip>)
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex flex-wrap gap-1">
                          {client.trusted ? <Chip tone="warn">{t("oauth.flag.trusted")}</Chip> : null}
                          {client.disabled ? (
                            <Chip tone="danger">{t("oauth.flag.disabled")}</Chip>
                          ) : (
                            <Chip tone="ok">{t("oauth.flag.enabled")}</Chip>
                          )}
                          {seeded ? <Chip>{t("oauth.flag.firstParty")}</Chip> : null}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => {
                              setCopied(false);
                              setConfirmTarget({ client, kind: "rotate" });
                            }}
                            className="px-2 py-1 rounded-chip bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 text-[11px] transition-colors duration-fast ease-soft cursor-pointer inline-flex items-center gap-1"
                          >
                            <RefreshCw className="w-3 h-3" />
                            <span>{t("oauth.rotate")}</span>
                          </button>
                          <button
                            type="button"
                            disabled={client.disabled}
                            onClick={() => void handleEnable(client)}
                            title={client.disabled ? "" : t("oauth.disableHint")}
                            className="px-2 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover text-text-body text-[11px] transition-colors duration-fast ease-soft disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                          >
                            {t("oauth.disable")}
                          </button>
                          <button
                            type="button"
                            disabled={seeded}
                            title={seeded ? t("oauth.seededHint") : ""}
                            onClick={() => {
                              setMessage(null);
                              setConfirmTarget({ client, kind: "delete" });
                            }}
                            className="px-2 py-1 rounded-chip bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 text-[11px] transition-colors duration-fast ease-soft disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer inline-flex items-center gap-1"
                          >
                            <Trash2 className="w-3 h-3" />
                            <span>{t("action.delete")}</span>
                          </button>
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

      <ConfirmDialog
        open={confirmTarget != null}
        title={
          confirmTarget?.kind === "rotate"
            ? t("oauth.rotateTitle")
            : confirmTarget?.kind === "delete"
              ? t("oauth.deleteTitle")
              : t("oauth.disableTitle")
        }
        message={confirmText()}
        confirmLabel={
          confirmTarget?.kind === "rotate"
            ? t("oauth.rotate")
            : confirmTarget?.kind === "delete"
              ? t("action.delete")
              : t("oauth.disable")
        }
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
