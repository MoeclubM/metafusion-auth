"use client";

// 语言切换：写 NEXT_LOCALE cookie（与主站同名同值），四个应用共用一份语言偏好。
import { useEffect, useRef, useState } from "react";
import { Check, Languages } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";
import { locales, type Locale } from "@/i18n/routing";

export function LocaleSwitcher() {
  const { locale, setLocale, t } = useI18n();
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => { if (!container.current?.contains(event.target as Node)) setOpen(false); };
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onPointer); document.removeEventListener("keydown", onKey); };
  }, [open]);
  return <div className="relative" ref={container}>
    <button type="button" aria-label={t("locale.label")} title={t("locale.label")} aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen(!open)} className="grid h-9 w-9 place-items-center rounded-full border border-line bg-surfaceSubtle text-text-body hover:bg-surfaceHover"><Languages className="h-4 w-4" /></button>
    {open ? <div role="menu" aria-label={t("locale.label")} className="absolute right-0 z-50 mt-2 w-44 rounded-card border border-line bg-surface p-1.5 shadow-elevated">
      {locales.map((code) => <button key={code} type="button" role="menuitemradio" aria-checked={locale === code} onClick={() => { setLocale(code as Locale); setOpen(false); }} className={"flex w-full items-center justify-between rounded-control px-3 py-2 text-left text-xs hover:bg-surfaceHover " + (locale === code ? "font-semibold text-primary" : "text-text-body")}>{t(`locale.${code}`)}{locale === code ? <Check className="h-4 w-4" /> : null}</button>)}
    </div> : null}
  </div>;
}
