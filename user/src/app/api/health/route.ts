import { NextResponse } from "next/server";

// 网关/编排的探活端点：暴露为 GET /api/health。
// 刻意不碰会话、不碰数据库：只回答“这个应用活着吗”。
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json({ ok: true, service: "auth-user" });
}
