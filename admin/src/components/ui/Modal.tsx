"use client";

import React from "react";
import { X } from "lucide-react";
import { useI18n } from "@/i18n/I18nProvider";

export function Modal({
  open,
  onClose,
  title,
  icon,
  children,
  maxWidth = "max-w-lg",
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  icon?: React.ReactNode;
  children: React.ReactNode;
  maxWidth?: string;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        className={`w-full ${maxWidth} rounded-panel border border-line bg-surface p-5 sm:p-6 space-y-4 shadow-elevated max-h-[90vh] overflow-y-auto`}
      >
        <div className="flex items-center justify-between border-b border-line/60 pb-3">
          <h3 className="text-sm font-semibold text-text-strong flex items-center gap-2">
            {icon}
            {title}
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="close"
            className="text-text-muted hover:text-text-strong p-2 rounded-control hover:bg-surfaceSubtle transition-colors duration-fast ease-soft grid place-items-center cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
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
    <Modal open={open} onClose={onClose} title={title} maxWidth="max-w-md">
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
