"use client";

// 界面收敛（"看不见"），不是鉴权：真正的判定在账号服务的 requirePermission。
// 缺权限时把这一块换成说明卡，页面其余部分照常可用。
import React from "react";
import { ForbiddenBlock } from "./ui/blocks";
import { useSession } from "@/lib/session";
import { can } from "@/lib/permissions";

export function RequirePermission({ code, children }: { code: string; children: React.ReactNode }) {
  const { user } = useSession();
  if (!can(user, code)) return <ForbiddenBlock permission={code} />;
  return <>{children}</>;
}
