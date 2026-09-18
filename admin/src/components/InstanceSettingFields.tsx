"use client";

// 实例设置页的字段渲染：可配置项（表单控件）/ 只读观测项（只展示）。
// 判定"能不能改"的逻辑不在这里——它在 lib/instanceSettings.ts 的 WRITABLE 上，
// 本文件只按传进来的 spec 选控件，避免"渲染说可写、提交说不可写"这种两处口径。

import React from "react";
import { Info } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { Chip, inputClass, labelClass } from "@/components/ui/blocks";
import {
  parseCodes,
  valueKind,
  RATE_LIMIT_MAX,
  RATE_LIMIT_MIN,
  type FieldSpec,
  type RawValue,
} from "@/lib/instanceSettings";

/** 分组小标题：可配置 / 只读观测两组共用。 */
export function GroupHeader({ icon, title, desc }: { icon: React.ReactNode; title: string; desc: string }) {
  return (
    <div className="flex items-start gap-2 px-1 pt-2">
      <span className="text-primary mt-0.5">{icon}</span>
      <div className="min-w-0">
        <h3 className="text-xs font-semibold text-text-strong">{title}</h3>
        <p className="text-[11px] text-text-muted leading-relaxed mt-0.5 max-w-3xl">{desc}</p>
      </div>
    </div>
  );
}

/** 只读观测项：拿到什么键就展示什么键，控件按值的实际类型选，并写明为什么只读。 */
export function ReadonlyRow({ settingKey, value, note }: { settingKey: string; value: unknown; note: string }) {
  const { t, tr } = useI18n();
  const kind = valueKind(value);
  const hint = tr(`instance.setting.${settingKey}.hint`, "");
  return (
    <div
      data-mf-setting-key={settingKey}
      data-mf-setting-group="readonly"
      className="p-3.5 rounded-card border border-line-subtle bg-surfaceSubtle space-y-2"
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-xs font-medium text-text-strong">{tr(`instance.setting.${settingKey}`, settingKey)}</span>
        <code className="text-[10px] font-mono text-text-faint break-all">{settingKey}</code>
        <Chip>{t("instance.readonlyTag")}</Chip>
      </div>

      {kind === "boolean" ? (
        <Chip tone={value ? "ok" : "neutral"}>{value ? t("instance.boolTrue") : t("instance.boolFalse")}</Chip>
      ) : null}
      {kind === "number" || kind === "string" ? (
        <div className="text-[11px] text-text-strong break-all">{String(value)}</div>
      ) : null}
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
      <p className="text-[10px] text-amber-400/80 leading-relaxed flex items-start gap-1.5">
        <Info className="w-3 h-3 shrink-0 mt-0.5" />
        <span>{note}</span>
      </p>
    </div>
  );
}

/**
 * 一个可配置项：控件种类来自服务端的值类型 + WRITABLE 的 spec。
 * raw 是控件的原始形态（未编辑时等于服务端值），dirty 表示它与服务端当前值不同。
 */
export function WritableField({
  settingKey,
  spec,
  label,
  hint,
  raw,
  dirty,
  busy,
  groupCodes,
  onEdit,
}: {
  settingKey: string;
  spec: FieldSpec;
  label: string;
  hint: string;
  raw: RawValue;
  dirty: boolean;
  busy: boolean;
  /** 已加载到的组码清单；为空表示拿不到清单（缺 auth.groups.manage），只能校验格式。 */
  groupCodes: string[];
  onEdit: (key: string, raw: RawValue) => void;
}) {
  const { t } = useI18n();
  const selected = spec.control === "stringArray" ? parseCodes(String(raw ?? "")) : [];

  return (
    <div
      data-mf-setting-key={settingKey}
      data-mf-setting-group="writable"
      className={`p-3.5 rounded-card border bg-surfaceSubtle space-y-2 ${dirty ? "border-primary/40" : "border-line-subtle"}`}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-xs font-medium text-text-strong">{label}</span>
        <code className="text-[10px] font-mono text-text-faint break-all">{settingKey}</code>
        {dirty ? <Chip tone="warn">{t("instance.pending")}</Chip> : null}
        {spec.impact === "high" ? <Chip tone="danger">{t("instance.impactHigh")}</Chip> : null}
      </div>

      {spec.control === "boolean" ? (
        <label className="inline-flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={raw === true}
            disabled={busy}
            onChange={(event) => onEdit(settingKey, event.target.checked)}
            className="accent-primary"
          />
          <span className="text-[11px] text-text-body">{raw === true ? t("instance.boolTrue") : t("instance.boolFalse")}</span>
        </label>
      ) : null}

      {spec.control === "number" ? (
        <div className="max-w-[12rem]">
          {/* 行标题已经写明"限流速率（次/分钟）"，这里不再叠一层同名标签，用 aria-label 保留无障碍名 */}
          <input
            aria-label={label}
            id={`instance-${settingKey}`}
            type="number"
            min={RATE_LIMIT_MIN}
            max={RATE_LIMIT_MAX}
            step={1}
            value={String(raw ?? "")}
            disabled={busy}
            onChange={(event) => onEdit(settingKey, event.target.value)}
            className={inputClass + " font-mono"}
          />
        </div>
      ) : null}

      {spec.control === "stringArray" ? (
        <div className="space-y-2">
          <label className={labelClass} htmlFor={`instance-${settingKey}`}>
            {t("instance.groupsLabel")}
          </label>
          <textarea
            id={`instance-${settingKey}`}
            rows={3}
            value={String(raw ?? "")}
            disabled={busy}
            onChange={(event) => onEdit(settingKey, event.target.value)}
            placeholder={t("instance.groupsPlaceholder")}
            className={inputClass + " font-mono resize-y"}
          />
          {groupCodes.length > 0 ? (
            <div className="space-y-1">
              <div className="text-[10px] font-mono text-text-faint">{t("instance.availableGroups")}</div>
              <div className="flex flex-wrap gap-1.5">
                {groupCodes.map((code) => {
                  const active = selected.includes(code);
                  return (
                    <button
                      key={code}
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        const next = active ? selected.filter((item) => item !== code) : [...selected, code];
                        onEdit(settingKey, next.join("\n"));
                      }}
                      className={`px-1.5 py-0.5 rounded-chip border text-[10px] font-mono transition-colors duration-fast ease-soft cursor-pointer disabled:opacity-50 ${
                        active
                          ? "bg-primary/15 text-primary border-primary/40"
                          : "bg-surfaceSubtle text-text-muted border-line hover:bg-surfaceHover"
                      }`}
                    >
                      {code}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            <p className="text-[10px] text-amber-400/80 leading-relaxed">{t("instance.groupsUnavailable")}</p>
          )}
        </div>
      ) : null}

      {hint ? <p className="text-[10px] text-text-faint leading-relaxed">{hint}</p> : null}
    </div>
  );
}
