import { NextResponse } from "next/server";

// 网关/编排的探活端点：经 basePath 暴露为 GET /admin/account/api/health。
//
// 刻意不碰会话、不碰数据库：健康检查要回答"这个应用活着吗"，登录态或上游抖动不该让它变红
// （账号服务本身的探活是网关的别的 location，不是这一条）。
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json({ ok: true, service: "auth-admin" });
}
