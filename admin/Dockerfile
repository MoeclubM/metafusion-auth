# syntax=docker/dockerfile:1
# ==============================================================================
# MetaFusion 账号管理台（auth-admin）
#
# 冻结契约（主仓库 deploy/docker-compose.yml 的 auth-admin 服务与 deploy/nginx.conf）：
#   build.context = 账号仓库根（${MF_AUTH_DIR:-../../metafusion-auth}），
#   build.dockerfile = admin/Dockerfile —— 因此下面所有 COPY 路径都相对**仓库根**，不是 admin/；
#   容器内端口 3000；网关把 /admin/account/ 反代到这里；健康端点 /admin/account/api/health。
#
# 多阶段 standalone 模式照抄主仓库 frontend/Dockerfile（样板），构建器用 Bun：
# Next 的 standalone 产物自带最小 server.js，运行时不需要 node_modules。
# ==============================================================================
FROM oven/bun:1.4-alpine AS base

FROM base AS deps
WORKDIR /app
# 锁文件用 bun.lock（bun 1.2+ 的文本格式；1.2 之前是二进制 bun.lockb，同一条 glob 都覆盖）。
COPY admin/package.json admin/bun.lock* admin/package-lock.json* ./
RUN --mount=type=cache,target=/root/.bun \
    bun install --frozen-lockfile 2>/dev/null || bun install

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY admin/ ./
ENV NEXT_TELEMETRY_DISABLED 1
# Bun 1.4 原生跑 Next 构建（比 Node 快 3-5 倍）
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
# Next standalone 的 server.js 为 Node 产物，Bun 可直接以 Node 兼容模式运行
CMD ["bun", "server.js"]
