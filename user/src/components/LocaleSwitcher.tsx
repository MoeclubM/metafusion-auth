"use client";

// 语言切换：写 NEXT_LOCALE cookie（与主站同名同值），四个应用共用一份语言偏好。
import React from "react";
import { Languages } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { locales, type Locale } from "@/i18n/routing";

export function LocaleSwitcher() {
  const { locale, setLocale, t } = useI18n();
  return (
    <label className="inline-flex items-center gap-1.5 text-[11px] text-text-muted">
      <Languages className="w-3.5 h-3.5" />
      <span className="sr-only">{t("locale.label")}</span>
      <select
        value={locale}
        onChange={(e) => setLocale(e.target.value as Locale)}
        aria-label={t("locale.label")}
        className="px-2 py-1 rounded-chip bg-surfaceSubtle border border-line text-[11px] text-text-body cursor-pointer outline-none"
      >
        {locales.map((code) => (
          <option key={code} value={code}>
            {t(`locale.${code}`)}
          </option>
        ))}
      </select>
    </label>
  );
}
