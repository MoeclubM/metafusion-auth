"use client";

// 审计留痕（只读）：过滤 + 分页列表。契约：docs/architecture/audit-log.md §5。
//
// 边界：唯一读取端点是账号服务的 GET /api/admin/audit-logs（权限码 auth.audit.read），
// 排序由服务端固定为 occurred_at DESC, id DESC；本页只做列表 + 过滤 + 分页——契约 §5 明确
// 不做导出/图表/详情抽屉。
//
// changes 的脱敏由写入侧负责（§4）：界面**原样展示** "[redacted]" 与 "a***@domain"，
// 不再二次加工——审计要的是库里真实的那一行。也正因为如此，这里不做"还原脱敏"之类的聪明事。

import React, { useCallback, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, FileClock, Search } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useResource } from "@/lib/useResource";
import { AUTH_AUDIT_READ } from "@/lib/permissions";
import { AUDIT_ERROR_KEYS } from "@/lib/errors";
import { formatStamp } from "@/lib/format";
import {
  AUDIT_PAGE_SIZE,
  AUDIT_SERVICES,
  fetchAuditLogs,
  type AuditLogPage,
  type AuditLogQuery,
} from "@/lib/endpoints";
import { RequirePermission } from "@/components/PermissionGate";
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
const EMPTY_PAGE: AuditLogPage = { items: [], total: 0, page: 1, per_page: AUDIT_PAGE_SIZE };

const DASH = "—";

const pagerButtonClass =
  "px-2.5 py-1 rounded-chip bg-surfaceSubtle hover:bg-surfaceHover border border-line text-[11px] text-text-body transition-colors duration-fast ease-soft cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center gap-1";

/** 表单草稿：值都是界面的形状（时间是无时区的本地墙钟），提交时才转成接口要的形状。 */
interface FilterDraft {
  service: string;
  action: string;
  actor: string;
  targetId: string;
  /** 空串 = 不过滤；其余只有 success / failure 两个合法值。 */
  result: string;
  from: string;
  to: string;
}

const emptyDraft = (): FilterDraft => ({
  service: "",
  action: "",
  actor: "",
  targetId: "",
  result: "",
  from: "",
  to: "",
});

/** 已提交的条件（含页码）：改草稿不等于改查询，点「查询」才生效。 */
interface AppliedQuery extends FilterDraft {
  page: number;
}

const INITIAL_QUERY: AppliedQuery = { ...emptyDraft(), page: 1 };

/**
 * datetime-local 是本地墙钟时间（不带时区），接口要 RFC3339。
 * 解析不了返回 null：宁可拦在表单里，也不发一个必然被 400 invalid_query 拒掉的串。
 */
function toRFC3339(local: string): string | null {
  if (!local) return "";
  const d = new Date(local);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

function buildQuery(applied: AppliedQuery): AuditLogQuery {
  return {
    service: applied.service.trim(),
    action: applied.action.trim(),
    actor: applied.actor.trim(),
    target_id: applied.targetId.trim(),
    result: applied.result,
    from: toRFC3339(applied.from) ?? "",
    to: toRFC3339(applied.to) ?? "",
    page: applied.page,
    per_page: AUDIT_PAGE_SIZE,
  };
}

/** changes 原样展示：折叠时给紧凑预览（遮罩值在这里就看得见），展开看缩进后的完整 JSON。 */
function ChangesCell({ value }: { value?: Record<string, unknown> | null }) {
  const text = useMemo(() => (value == null ? "" : JSON.stringify(value)), [value]);
  if (!text || text === "{}") return <span className="text-[10px] font-mono text-text-faint">{DASH}</span>;
  const preview = text.length > 80 ? text.slice(0, 80) + "…" : text;
  return (
    <details className="max-w-sm">
      <summary className="cursor-pointer font-mono text-[10px] text-text-muted break-all">{preview}</summary>
      <pre className="mt-1 p-2 rounded-control bg-surfaceSubtle border border-line-subtle text-[10px] font-mono text-text-body whitespace-pre-wrap break-all overflow-auto max-h-48">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className={labelClass} htmlFor={id}>
        {label}
      </label>
      {children}
      {hint ? <p className="mt-1 text-[10px] text-text-faint leading-relaxed">{hint}</p> : null}
    </div>
  );
}

function AuditPanel() {
  const { t, locale } = useI18n();

  const [draft, setDraft] = useState<FilterDraft>(emptyDraft());
  const [applied, setApplied] = useState<AppliedQuery>(INITIAL_QUERY);
  const [formError, setFormError] = useState<string | null>(null);

  // loader 只在已提交条件变化时换引用：useResource 依赖它，草稿改动不触发取数。
  const load = useCallback(() => fetchAuditLogs(buildQuery(applied)), [applied]);
  // AUDIT_ERROR_KEYS 是模块级常量，满足 useResource 对稳定引用的要求。
  const logs = useResource(load, EMPTY_PAGE, AUTH_AUDIT_READ, AUDIT_ERROR_KEYS);

  const totalPages = Math.max(1, Math.ceil(logs.data.total / (logs.data.per_page || AUDIT_PAGE_SIZE)));

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const from = toRFC3339(draft.from);
    const to = toRFC3339(draft.to);
    if (from === null || to === null) {
      setFormError(t("audit.filter.timeInvalid"));
      return;
    }
    // 起止都是闭区间：倒着的区间查出来必然是空的，先拦住而不是让人对着空列表猜。
    if (from && to && from > to) {
      setFormError(t("audit.filter.rangeReversed"));
      return;
    }
    setFormError(null);
    setApplied({ ...draft, page: 1 });
  };

  const reset = () => {
    setFormError(null);
    setDraft(emptyDraft());
    setApplied(INITIAL_QUERY);
  };

  const goto = (page: number) => setApplied((prev) => ({ ...prev, page }));

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<FileClock className="w-4 h-4 text-primary" />}
        title={t("audit.title")}
        desc={t("audit.desc")}
        actions={<RefreshButton onClick={logs.reload} loading={logs.loading} />}
      />

      <form onSubmit={submit} className="p-4 rounded-card bg-surfaceSubtle border border-line-subtle space-y-3">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field
            id="audit-service"
            label={t("audit.filter.service")}
            hint={t("audit.filter.serviceHint", { services: AUDIT_SERVICES.join(" / ") })}
          >
            <input
              id="audit-service"
              type="text"
              list="audit-service-options"
              value={draft.service}
              onChange={(e) => setDraft((prev) => ({ ...prev, service: e.target.value }))}
              className={inputClass + " font-mono"}
            />
            <datalist id="audit-service-options">
              {AUDIT_SERVICES.map((service) => (
                <option key={service} value={service} />
              ))}
            </datalist>
          </Field>

          <Field id="audit-action" label={t("audit.filter.action")} hint={t("audit.filter.actionHint")}>
            <input
              id="audit-action"
              type="text"
              value={draft.action}
              onChange={(e) => setDraft((prev) => ({ ...prev, action: e.target.value }))}
              className={inputClass + " font-mono"}
              placeholder={t("audit.filter.actionPlaceholder")}
            />
          </Field>

          <Field id="audit-actor" label={t("audit.filter.actor")} hint={t("audit.filter.actorHint")}>
            <input
              id="audit-actor"
              type="text"
              value={draft.actor}
              onChange={(e) => setDraft((prev) => ({ ...prev, actor: e.target.value }))}
              className={inputClass + " font-mono"}
            />
          </Field>

          <Field id="audit-target" label={t("audit.filter.targetId")}>
            <input
              id="audit-target"
              type="text"
              value={draft.targetId}
              onChange={(e) => setDraft((prev) => ({ ...prev, targetId: e.target.value }))}
              className={inputClass + " font-mono"}
            />
          </Field>

          <Field id="audit-result" label={t("audit.filter.result")}>
            <select
              id="audit-result"
              value={draft.result}
              onChange={(e) => setDraft((prev) => ({ ...prev, result: e.target.value }))}
              className={inputClass}
            >
              <option value="">{t("audit.filter.resultAll")}</option>
              <option value="success">{t("audit.result.success")}</option>
              <option value="failure">{t("audit.result.failure")}</option>
            </select>
          </Field>

          <Field id="audit-from" label={t("audit.filter.from")}>
            <input
              id="audit-from"
              type="datetime-local"
              value={draft.from}
              onChange={(e) => setDraft((prev) => ({ ...prev, from: e.target.value }))}
              className={inputClass + " font-mono"}
            />
          </Field>

          <Field id="audit-to" label={t("audit.filter.to")}>
            <input
              id="audit-to"
              type="datetime-local"
              value={draft.to}
              onChange={(e) => setDraft((prev) => ({ ...prev, to: e.target.value }))}
              className={inputClass + " font-mono"}
            />
          </Field>
        </div>

        <p className="text-[10px] text-text-faint leading-relaxed">{t("audit.filter.timeHint")}</p>

        <div className="flex items-center gap-2">
          <button type="submit" className={primaryButtonClass + " inline-flex items-center gap-1.5"}>
            <Search className="w-3.5 h-3.5" />
            <span>{t("audit.apply")}</span>
          </button>
          <button type="button" onClick={reset} className={pagerButtonClass}>
            {t("audit.reset")}
          </button>
        </div>

        {formError ? <StatusMessage kind="err" text={formError} /> : null}
      </form>

      {logs.error ? (
        <ErrorNotice message={logs.error} onRetry={logs.reload} permissionHint={t("audit.needPermission")} />
      ) : null}

      {logs.loading && logs.data.items.length === 0 ? <LoadingBlock /> : null}
      {!logs.loading && !logs.error && logs.data.items.length === 0 ? <EmptyBlock text={t("audit.empty")} /> : null}

      {logs.data.items.length > 0 ? (
        <div className="rounded-card border border-line-subtle bg-surface/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-line-subtle bg-surfaceSubtle text-text-muted font-mono">
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.time")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.service")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.action")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.actor")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.target")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.result")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.request")}</th>
                  <th className="py-2.5 px-3 font-medium">{t("audit.col.changes")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-subtle">
                {logs.data.items.map((entry) => (
                  <tr key={entry.id} className="align-top hover:bg-surfaceSubtle transition-colors duration-fast ease-soft">
                    <td className="py-2.5 px-3 font-mono text-[11px] text-text-muted whitespace-nowrap">
                      {formatStamp(entry.occurred_at, locale)}
                    </td>
                    <td className="py-2.5 px-3">
                      <Chip>{entry.service}</Chip>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-text-strong break-all">{entry.action}</td>
                    <td className="py-2.5 px-3">
                      <div className="font-mono text-[11px] text-text-body">{entry.actor_username || DASH}</div>
                      <div className="flex flex-wrap items-center gap-1.5 mt-1">
                        {entry.credential_type ? <Chip>{entry.credential_type}</Chip> : null}
                        {entry.actor_ip ? (
                          <span className="text-[10px] font-mono text-text-faint">{entry.actor_ip}</span>
                        ) : null}
                      </div>
                      {entry.actor_user_id ? (
                        <div className="mt-1 text-[10px] font-mono text-text-faint break-all">{entry.actor_user_id}</div>
                      ) : null}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-text-body break-all">
                      {entry.target_type || entry.target_id
                        ? `${entry.target_type ?? ""}${entry.target_type && entry.target_id ? ":" : ""}${entry.target_id ?? ""}`
                        : DASH}
                    </td>
                    <td className="py-2.5 px-3">
                      {entry.result === "success" ? (
                        <Chip tone="ok">{t("audit.result.success")}</Chip>
                      ) : entry.result === "failure" ? (
                        <Chip tone="danger">{t("audit.result.failure")}</Chip>
                      ) : (
                        <span className="text-[10px] font-mono text-text-faint">{entry.result || DASH}</span>
                      )}
                      {entry.error_code ? (
                        <div className="mt-1 text-[10px] font-mono text-rose-300 break-all">{entry.error_code}</div>
                      ) : null}
                      {entry.http_status ? (
                        <div className="mt-1 text-[10px] font-mono text-text-faint">HTTP {entry.http_status}</div>
                      ) : null}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[10px] text-text-muted">
                      <div className="text-text-body break-all">
                        {[entry.request_method, entry.route].filter(Boolean).join(" ") || DASH}
                      </div>
                      {entry.request_id ? (
                        <div className="mt-1 break-all" title={t("audit.requestId")}>
                          {entry.request_id}
                        </div>
                      ) : null}
                    </td>
                    <td className="py-2.5 px-3">
                      <ChangesCell value={entry.changes} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {!logs.error && logs.data.total > 0 ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[11px] text-text-faint font-mono">{t("audit.total", { count: logs.data.total })}</p>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={logs.loading || applied.page <= 1}
              onClick={() => goto(applied.page - 1)}
              className={pagerButtonClass}
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>{t("audit.prev")}</span>
            </button>
            <span className="text-[11px] font-mono text-text-muted">
              {t("audit.page", { page: applied.page, pages: totalPages })}
            </span>
            <button
              type="button"
              disabled={logs.loading || applied.page >= totalPages}
              onClick={() => goto(applied.page + 1)}
              className={pagerButtonClass}
            >
              <span>{t("audit.next")}</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function AuditPage() {
  return (
    <RequirePermission code={AUTH_AUDIT_READ}>
      <AuditPanel />
    </RequirePermission>
  );
}
