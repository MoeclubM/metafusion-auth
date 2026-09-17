"use client";

// 实例与设置：只读展示账号服务实际返回的实例设置，以及当前身份持有的权限。
//
// 只读是本页的刻意边界：渲染完全由接口返回驱动——拿到什么键就渲染什么键，控件按值的类型选。
// 后端新增设置项时这里不用改代码；instance.setting.<key> 只是可选的标签/说明覆盖层，
// 缺了会回退成键名。**拿不到的项不编**：接口没返回的键这里不会出现，也不会填占位值。

import React, { useMemo } from "react";
import { Info, ServerCog } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useSession } from "@/lib/session";
import { useResource } from "@/lib/useResource";
import { AUTH_SETTINGS_MANAGE } from "@/lib/permissions";
import { fetchAdminSettings, type SettingsMap } from "@/lib/endpoints";
import { RequirePermission } from "@/components/PermissionGate";
import {
  Chip,
  EmptyBlock,
  ErrorNotice,
  LoadingBlock,
  RefreshButton,
  SectionHeader,
} from "@/components/ui/blocks";

// 模块级常量：useResource 的 initial 必须是稳定引用。
const EMPTY_SETTINGS: SettingsMap = {};

type ValueKind = "boolean" | "number" | "string" | "stringArray" | "json";

/** 控件种类只看值的实际类型，不看键名。 */
function valueKind(value: unknown): ValueKind {
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return "stringArray";
  return "json";
}

function SettingsPanel() {
  const { t, tr } = useI18n();
  const { user } = useSession();
  const settings = useResource(fetchAdminSettings, EMPTY_SETTINGS, AUTH_SETTINGS_MANAGE);

  const keys = useMemo(() => Object.keys(settings.data ?? EMPTY_SETTINGS), [settings.data]);
  const permissions = user?.permissions ?? [];

  return (
    <div className="space-y-4">
      <SectionHeader
        icon={<ServerCog className="w-4 h-4 text-primary" />}
        title={t("instance.title")}
        desc={t("instance.desc")}
        actions={<RefreshButton onClick={settings.reload} loading={settings.loading} />}
      />

      <div className="p-3 rounded-card bg-sky-500/[0.06] border border-sky-500/20 flex items-start gap-2">
        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-sky-300" />
        <p className="text-[11px] text-sky-100/80 leading-relaxed">{t("instance.readonly")}</p>
      </div>

      {settings.error ? (
        <ErrorNotice message={settings.error} onRetry={settings.reload} permissionHint={t("instance.needPermission")} />
      ) : null}

      {settings.loading && keys.length === 0 ? <LoadingBlock /> : null}
      {!settings.loading && !settings.error && keys.length === 0 ? <EmptyBlock text={t("instance.empty")} /> : null}

      <div className="space-y-2">
        {keys.map((key) => {
          const value = settings.data[key];
          const kind = valueKind(value);
          const hint = tr(`instance.setting.${key}.hint`, "");
          return (
            <div key={key} className="p-3.5 rounded-card border border-line-subtle bg-surfaceSubtle space-y-2">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="text-xs font-medium text-text-strong">{tr(`instance.setting.${key}`, key)}</span>
                <code className="text-[10px] font-mono text-text-faint break-all">{key}</code>
              </div>

              {kind === "boolean" ? (
                <Chip tone={value ? "ok" : "neutral"}>{value ? t("instance.boolTrue") : t("instance.boolFalse")}</Chip>
              ) : null}

              {kind === "number" ? (
                <div className="font-mono text-[11px] text-text-strong">{String(value)}</div>
              ) : null}

              {kind === "string" ? <div className="text-[11px] text-text-strong break-all">{String(value)}</div> : null}

              {kind === "stringArray" ? (
                <div className="flex flex-wrap gap-1.5">
                  {(value as string[]).length === 0 ? (
                    <span className="text-[10px] font-mono text-text-faint">—</span>
                  ) : (
                    (value as string[]).map((item) => <Chip key={item}>{item}</Chip>)
                  )}
                </div>
              ) : null}

              {kind === "json" ? (
                <pre className="p-2 rounded-control bg-surface border border-line text-[10px] font-mono text-text-body overflow-x-auto">
                  {JSON.stringify(value, null, 2)}
                </pre>
              ) : null}

              {hint ? <p className="text-[10px] text-text-faint leading-relaxed">{hint}</p> : null}
            </div>
          );
        })}
      </div>

      <div className="p-4 rounded-card bg-surfaceSubtle border border-line-subtle space-y-3">
        <h3 className="text-sm font-semibold text-text-strong">{t("instance.identityTitle")}</h3>
        <p className="text-[11px] text-text-muted leading-relaxed">{t("instance.identityDesc")}</p>
        <div className="grid gap-2 sm:grid-cols-2 text-[11px]">
          <div className="space-y-0.5">
            <div className="font-mono text-text-faint">{t("instance.identityUsername")}</div>
            <div className="text-text-strong break-all">{user?.username ?? "—"}</div>
          </div>
          <div className="space-y-0.5">
            <div className="font-mono text-text-faint">{t("instance.identityId")}</div>
            <div className="text-text-strong break-all font-mono">{user?.id ?? "—"}</div>
          </div>
          <div className="space-y-0.5">
            <div className="font-mono text-text-faint">{t("instance.identityRole")}</div>
            <div className="text-text-strong font-mono">{user?.role ?? "—"}</div>
          </div>
          <div className="space-y-0.5">
            <div className="font-mono text-text-faint">{t("instance.identityGroups")}</div>
            <div className="flex flex-wrap gap-1">
              {(user?.groups ?? []).length === 0 ? (
                <span className="text-text-faint font-mono">—</span>
              ) : (
                (user?.groups ?? []).map((code) => <Chip key={code}>{code}</Chip>)
              )}
            </div>
          </div>
        </div>
        <div className="space-y-1">
          <div className="font-mono text-[11px] text-text-faint">{t("instance.identityPermissions")}</div>
          <div className="flex flex-wrap gap-1">
            {permissions.length === 0 ? (
              <span className="text-[10px] font-mono text-text-faint">{t("instance.identityNoPermissions")}</span>
            ) : (
              permissions.map((code) => <Chip key={code}>{code}</Chip>)
            )}
          </div>
          <p className="text-[10px] text-text-faint leading-relaxed">{t("instance.identityPermissionsHint")}</p>
        </div>
      </div>
    </div>
  );
}

export default function InstancePage() {
  return (
    <RequirePermission code={AUTH_SETTINGS_MANAGE}>
      <SettingsPanel />
    </RequirePermission>
  );
}
