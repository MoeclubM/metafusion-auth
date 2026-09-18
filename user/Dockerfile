# syntax=docker/dockerfile:1
# ==============================================================================
# MetaFusion 账号自助应用（auth-user：登录/注册/初始化）
#
# 冻结契约（主仓库 deploy/docker-compose.yml 的 auth-user 服务与 deploy/nginx.conf）：
#   build.context = 账号仓库根，build.dockerfile = user/Dockerfile —— 下面所有 COPY
#   路径都相对仓库根，不是 user/；容器内端口 3000；网关把 = /login、= /setup
#   精确路径反代到这里；健康端点 GET /api/health。
#
# 多阶段 standalone 模式照抄 admin/Dockerfile（样板），构建器用 Bun。
# ==============================================================================
FROM oven/bun:1.4-alpine AS base

FROM base AS deps
WORKDIR /app
COPY user/package.json user/bun.lock* user/package-lock.json* ./
RUN --mount=type=cache,target=/root/.bun \
    bun install --frozen-lockfile 2>/dev/null || bun install

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY user/ ./
ENV NEXT_TELEMETRY_DISABLED 1
RUN --mount=type=cache,target=/app/.next/cache \
    bun run build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
RUN mkdir -p .next && chown nextjs:nodejs .next
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT 3000
ENV HOSTNAME "0.0.0.0"
CMD ["bun", "server.js"]
