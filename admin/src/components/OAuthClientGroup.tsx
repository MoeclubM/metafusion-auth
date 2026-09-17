"use client";

// OAuth 客户端分组表：一个分组 = 标题 + "这组是什么、去哪儿维护" + 该组的行。
//
// 纯呈现：不取数、不发请求，动作由页面（app/oauth-clients/page.tsx）注入——
// "谁能改什么"只在一个地方判定，表里不重复做判断。

import React from "react";
import { RefreshCw, Trash2 } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { formatStamp } from "@/lib/format";
import { isSystemClient, SEEDED_CLIENT_IDS, type OAuthClient } from "@/lib/endpoints";
import { Chip, EmptyBlock } from "@/components/ui/blocks";

export interface OAuthClientActions {
  onRotate: (client: OAuthClient) => void;
  /** 启用中的客户端走二次确认停用；已停用的直接启用。 */
  onToggleDisabled: (client: OAuthClient) => void;
  onDelete: (client: OAuthClient) => void;
}

export function OAuthClientGroup({
  title,
  desc,
  emptyText,
  clients,
  actions,
}: {
  title: string;
  desc: string;
  /** 本组为空时的说明：分组后"空表"必须说清是这一组空，而不是整页没数据。 */
  emptyText: string;
  clients: OAuthClient[];
  actions: OAuthClientActions;
}) {
  const { t, locale } = useI18n();
  const { onRotate, onToggleDisabled, onDelete } = actions;

  return (
    <section className="space-y-2">
      <div>
        <h3 className="text-xs font-semibold text-text-strong flex items-center gap-2">
          <span>{title}</span>
          <span className="font-mono text-[10px] text-text-muted">{clients.length}</span>
        </h3>
        <p className="text-[11px] text-text-muted leading-relaxed mt-1 max-w-3xl">{desc}</p>
      </div>

      {clients.length === 0 ? (
        <EmptyBlock text={emptyText} />
      ) : (
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
                {clients.map((client) => {
                  const system = isSystemClient(client);
                  const seeded = SEEDED_CLIENT_IDS.has(client.client_id);
                  return (
                    <tr key={client.client_id} className="hover:bg-surfaceSubtle transition-colors duration-fast ease-soft">
                      <td className="py-2.5 px-3">
                        <div className="font-mono text-[11px] text-text-strong">{client.client_id}</div>
                        <div className="text-[10px] text-text-muted">{client.name}</div>
                        {system ? null : (
                          <div className="text-[10px] text-text-faint">
                            {t("oauth.owner", { owner: client.owner_username || client.owner_user_id || "" })}
                          </div>
                        )}
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
                          {system ? <Chip tone="ok">{t("oauth.flag.firstParty")}</Chip> : null}
                          {/* 系统应用免同意，展示上恒为已核验；第三方按接口返回的 verified 如实显示。 */}
                          {system || client.verified ? (
                            <Chip tone="ok">{t("oauth.flag.verified")}</Chip>
                          ) : (
                            <Chip tone="warn">{t("oauth.flag.unverified")}</Chip>
                          )}
                          {client.trusted ? <Chip tone="warn">{t("oauth.flag.trusted")}</Chip> : null}
                          {client.disabled ? (
                            <Chip tone="danger">{t("oauth.flag.disabled")}</Chip>
                          ) : (
                            <Chip tone="ok">{t("oauth.flag.enabled")}</Chip>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => onRotate(client)}
                            className="px-2 py-1 rounded-chip bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 text-[11px] transition-colors duration-fast ease-soft cursor-pointer inline-flex items-center gap-1"
                          >
                            <RefreshCw className="w-3 h-3" />
                            <span>{t("oauth.rotate")}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => onToggleDisabled(client)}
                            title={client.disabled ? "" : t("oauth.disableHint")}
                            className="px-2 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover text-text-body text-[11px] transition-colors duration-fast ease-soft disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                          >
                            {client.disabled ? t("oauth.enable") : t("oauth.disable")}
                          </button>
                          <button
                            type="button"
                            disabled={seeded}
                            title={seeded ? t("oauth.seededHint") : ""}
                            onClick={() => onDelete(client)}
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
      )}
    </section>
  );
}
