"use client";

import React from "react";
import { X } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const dialogStack: HTMLElement[] = [];
let originalOverflow = "";

export function Modal({ open, onClose, title, icon, children, maxWidth = "max-w-lg", busy = false }: {
  open: boolean; onClose: () => void; title: React.ReactNode; icon?: React.ReactNode;
  children: React.ReactNode; maxWidth?: string; busy?: boolean;
}) {
  const { t } = useI18n();
  const titleId = React.useId();
  const panel = React.useRef<HTMLDivElement>(null);
  const latest = React.useRef({onClose, busy});
  latest.current = {onClose, busy};
  const close = () => { if (!latest.current.busy) latest.current.onClose(); };
  React.useEffect(() => {
    if (!open || !panel.current) return;
    const element = panel.current;
    const previous = document.activeElement as HTMLElement | null;
    dialogStack.push(element);
    if (dialogStack.length === 1) { originalOverflow = document.body.style.overflow; document.body.style.overflow = "hidden"; }
    const items = () => Array.from(element.querySelectorAll<HTMLElement>(FOCUSABLE));
    (items()[0] ?? element).focus();
    const onKey = (e: KeyboardEvent) => {
      if (dialogStack.at(-1) !== element) return;
      if (e.key === "Escape") { e.preventDefault(); close(); }
      if (e.key !== "Tab") return;
      const all = items(); const first = all[0]; const last = all.at(-1);
      if (!first || !last) { e.preventDefault(); element.focus(); }
      else if (e.shiftKey && (document.activeElement === first || document.activeElement === element || !element.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      const index = dialogStack.indexOf(element); if (index >= 0) dialogStack.splice(index, 1);
      if (!dialogStack.length) document.body.style.overflow = originalOverflow;
      if (previous?.isConnected) previous.focus();
    };
  }, [open]);
  if (!open) return null;
  return <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}>
    <div ref={panel} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}
      className={`w-full ${maxWidth} min-w-0 rounded-panel border border-line bg-surface p-5 sm:p-6 space-y-4 shadow-elevated max-h-[90vh] overflow-y-auto outline-none`}>
      <div className="flex items-center justify-between gap-3 border-b border-line/60 pb-3">
        <h3 id={titleId} className="min-w-0 break-words text-sm font-semibold text-text-strong flex items-center gap-2">{icon}{title}</h3>
        <button type="button" onClick={close} disabled={busy} aria-label={t("action.close")} className="shrink-0 rounded-control p-2 text-text-muted hover:bg-surfaceSubtle disabled:opacity-50"><X className="h-4 w-4" aria-hidden="true" /></button>
      </div>
      {children}
    </div>
  </div>;
}

/** 破坏性动作的二次确认：确认按钮必须显式点一次，不做"回车即提交"。 */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  busy,
  danger = true,
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  message: React.ReactNode;
  confirmLabel: string;
  busy?: boolean;
  danger?: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const { t } = useI18n();
  return (
    <Modal open={open} onClose={onClose} title={title} maxWidth="max-w-md" busy={busy}>
      <div className="text-xs text-text-body leading-relaxed space-y-3">
        <div>{message}</div>
        <div className="flex justify-end gap-2 pt-1">
          <CancelButton onClick={onClose} disabled={busy} label={t("action.cancel")} />
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className={`px-4 py-1.5 rounded-control text-white text-xs font-semibold transition-colors duration-fast ease-soft disabled:opacity-50 cursor-pointer ${
              danger ? "bg-rose-500 hover:bg-rose-400" : "bg-primary hover:bg-primary-hover"
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function CancelButton({
  onClick,
  disabled,
  label,
}: {
  onClick: () => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="px-3 py-1.5 rounded-control bg-surfaceSubtle hover:bg-surfaceHover border border-line text-text-body text-xs transition-colors duration-fast ease-soft disabled:opacity-50 cursor-pointer"
    >
      {label ?? "—"}
    </button>
  );
}
