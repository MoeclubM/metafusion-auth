"use client";

// 实例与设置：实例设置的**唯一 UI 写入点**（GET / PUT /api/admin/settings）。
//
// 字段分两组，判据只有一条——**服务端接受写入、且仓库里真有代码消费**：
//   · 可配置：见 lib/instanceSettings.ts 的 WRITABLE（每项都注明了消费点）；
//   · 只读观测：服务端接受写入但无人消费的键（site_name / require_email_verification），
//     加上没有登记过的未知新键。给它们做输入框等于让人改一个不生效的字段。
//
// 契约来源：internal/handler/handler.go（路由与响应形状）、
// internal/store/access.go（DefaultSettings 的键、UpdateSettings 的接受表与取值约束）。
// PUT 是**补丁**语义：只提交改动过的键，未知键会被拒（invalid_setting）。
//
// 权限：进入本页与写入都要求 auth.settings.manage；界面隐藏只是"看不见"，
// 服务端 requirePermission 才是唯一授权断言。影响准入/防护的改动保存前过二次确认。

import React, { useMemo, useState } from "react";
import { Info, Pencil, ServerCog, Telescope } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { useSession } from "@/lib/session";
import { useResource } from "@/lib/useResource";
import { AUTH_GROUPS_MANAGE, AUTH_SETTINGS_MANAGE } from "@/lib/permissions";
import { describeCodedError, SETTINGS_ERROR_KEYS } from "@/lib/errors";
import { fetchAdminGroups, fetchAdminSettings, updateAdminSettings, type AdminGroup, type SettingsMap } from "@/lib/endpoints";
import {
  HIGH_IMPACT_KEYS,
  UNWRITABLE_REASON,
  WRITABLE,
  describeValue,
  isLoweringRateLimit,
  rawForm,
  submitValue,
  validatePending,
  type Edits,
  type RawValue,
} from "@/lib/instanceSettings";
import { RequirePermission } from "@/components/PermissionGate";
import { GroupHeader, ReadonlyRow, WritableField } from "@/components/InstanceSettingFields";
import { CancelButton, ConfirmDialog } from "@/components/ui/Modal";
import {
  Chip,
  EmptyBlock,
  ErrorNotice,
  LoadingBlock,
  primaryButtonClass,
  RefreshButton,
  SectionHeader,
  StatusMessage,
} from "@/components/ui/blocks";

// 模块级常量：useResource 的 initial 必须是稳定引用。
const EMPTY_SETTINGS: SettingsMap = {};
const EMPTY_GROUPS: AdminGroup[] = [];

function SettingsPanel() {
  const { t, tr } = useI18n();
  const { user } = useSession();
  const settings = useResource(fetchAdminSettings, EMPTY_SETTINGS, AUTH_SETTINGS_MANAGE);
  // 组清单只用于校验「新账号默认权限组」的组码是否存在；缺 auth.groups.manage 时降级为"无法确认"。
  const groups = useResource(fetchAdminGroups, EMPTY_GROUPS, AUTH_GROUPS_MANAGE);

  const [edits, setEdits] = useState<Edits>({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const data = settings.data ?? EMPTY_SETTINGS;
  const keys = useMemo(() => Object.keys(data), [data]);
  const writableKeys = useMemo(() => keys.filter((key) => WRITABLE[key] !== undefined), [keys]);
  const readonlyKeys = useMemo(() => keys.filter((key) => WRITABLE[key] === undefined), [keys]);
  const groupCodes = useMemo(() => groups.data.map((group) => group.code), [groups.data]);

  /** 待保存的键：只看**与当前服务端值不同**的编辑——改了又改回去不算改动。 */
  const pendingKeys = useMemo(
    () =>
      Object.keys(edits).filter((key) => {
        const spec = WRITABLE[key];
        return spec ? rawForm(data[key], spec) !== edits[key] : false;
      }),
    [edits, data]
  );

  const label = (key: string) => tr(`instance.setting.${key}`, key);

  const setEdit = (key: string, raw: RawValue) => {
    setMessage(null);
    setEdits((prev) => ({ ...prev, [key]: raw }));
  };

  const reset = () => {
    setEdits({});
    setMessage(null);
  };

  const runSave = async (pending: string[]) => {
    const patch: SettingsMap = {};
    for (const key of pending) {
      const spec = WRITABLE[key];
      if (spec) patch[key] = submitValue(edits[key] ?? "", spec);
    }
    const summary = pending.map(label).join("、");
    setBusy(true);
    setMessage(null);
    try {
      await updateAdminSettings(patch);
      // 成功才清空草稿：失败时保留输入，用户改一个数字重试即可。
      setEdits({});
      setMessage({ kind: "ok", text: t("instance.saved", { keys: summary }) });
      settings.reload();
    } catch (err) {
      setMessage({ kind: "err", text: describeCodedError(err, t, AUTH_SETTINGS_MANAGE, SETTINGS_ERROR_KEYS) });
    } finally {
      setBusy(false);
      setConfirmOpen(false);
    }
  };

  const handleSave = () => {
    setMessage(null);
    if (pendingKeys.length === 0) {
      setMessage({ kind: "err", text: t("instance.noChanges") });
      return;
    }
    const invalid = validatePending(pendingKeys, edits, groupCodes);
    if (invalid) {
      setMessage({ kind: "err", text: t(invalid.key, invalid.vars) });
      return;
    }
    const needsConfirm = pendingKeys.some((key) => HIGH_IMPACT_KEYS.includes(key));
    if (!needsConfirm && !isLoweringRateLimit(pendingKeys, edits, data["auth_rate_limit_per_minute"])) {
      void runSave(pendingKeys);
      return;
    }
    setConfirmOpen(true);
  };

  const changeLines = pendingKeys.map((key) => {
    const spec = WRITABLE[key];
    const before = describeValue(data[key], t);
    const after = spec ? describeValue(submitValue(edits[key] ?? "", spec), t) : "";
    return { key, text: t("instance.changeLine", { label: label(key), from: before, to: after }) };
  });

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
        <p className="text-[11px] text-sky-100/80 leading-relaxed">{t("instance.writeHint")}</p>
      </div>

      {message ? (
        <div data-mf-settings-message={message.kind}>
          <StatusMessage kind={message.kind} text={message.text} />
        </div>
      ) : null}

      {settings.error ? (
        <ErrorNotice message={settings.error} onRetry={settings.reload} permissionHint={t("instance.needPermission")} />
      ) : null}

      {settings.loading && keys.length === 0 ? <LoadingBlock /> : null}
      {!settings.loading && !settings.error && keys.length === 0 ? <EmptyBlock text={t("instance.empty")} /> : null}

      {writableKeys.length > 0 ? (
        <div className="space-y-2">
          <GroupHeader
            icon={<Pencil className="w-3.5 h-3.5" />}
            title={t("instance.writableTitle")}
            desc={t("instance.writableDesc")}
          />

          {writableKeys.map((key) => {
            const spec = WRITABLE[key];
            if (!spec) return null;
            return (
              <WritableField
                key={key}
                settingKey={key}
                spec={spec}
                label={label(key)}
                hint={tr(`instance.setting.${key}.hint`, "")}
                raw={key in edits ? edits[key] : rawForm(data[key], spec)}
                dirty={pendingKeys.includes(key)}
                busy={busy}
                groupCodes={groupCodes}
                onEdit={setEdit}
              />
            );
          })}

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              type="button"
              data-mf-settings-save=""
              onClick={handleSave}
              disabled={busy || pendingKeys.length === 0}
              className={primaryButtonClass}
            >
              {busy ? t("action.saving") : t("action.save")}
            </button>
            <CancelButton onClick={reset} disabled={busy || pendingKeys.length === 0} label={t("instance.reset")} />
            <span className="text-[11px] font-mono text-text-faint">
              {pendingKeys.length === 0 ? t("instance.noChanges") : t("instance.changeCount", { count: pendingKeys.length })}
            </span>
          </div>
        </div>
      ) : null}

      {readonlyKeys.length > 0 ? (
        <div className="space-y-2">
          <GroupHeader
            icon={<Telescope className="w-3.5 h-3.5" />}
            title={t("instance.readonlyTitle")}
            desc={t("instance.readonlyDesc")}
          />
          {readonlyKeys.map((key) => (
            <ReadonlyRow
              key={key}
              settingKey={key}
              value={data[key]}
              note={tr(UNWRITABLE_REASON[key] ?? "instance.why.unknown", UNWRITABLE_REASON[key] ?? "")}
            />
          ))}
        </div>
      ) : null}

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
            {(user?.permissions ?? []).length === 0 ? (
              <span className="text-[10px] font-mono text-text-faint">{t("instance.identityNoPermissions")}</span>
            ) : (
              (user?.permissions ?? []).map((code) => <Chip key={code}>{code}</Chip>)
            )}
          </div>
          <p className="text-[10px] text-text-faint leading-relaxed">{t("instance.identityPermissionsHint")}</p>
        </div>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        title={t("instance.confirmTitle")}
        message={
          <div className="space-y-2">
            <p className="text-[11px] leading-relaxed">{t("instance.confirmDesc")}</p>
            <ul className="space-y-1">
              {changeLines.map(({ key, text }) => (
                <li key={key} className="font-mono text-[11px] text-text-strong leading-relaxed">
                  {text}
                </li>
              ))}
            </ul>
          </div>
        }
        confirmLabel={t("instance.confirmApply")}
        busy={busy}
        onClose={() => setConfirmOpen(false)}
        onConfirm={() => void runSave(pendingKeys)}
      />
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
