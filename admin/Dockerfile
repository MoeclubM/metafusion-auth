# syntax=docker/dockerfile:1
# ==============================================================================
# MetaFusion Auth Admin — Next.js standalone on Bun 1.4
#
# 端口与 basePath 是跨仓库契约：容器内监听 3000，主仓库 compose 里网关的上游名是
# auth-admin:3000，页面挂载在 /admin/account（见 next.config.mjs）。改这三样前先改主仓库。
#
# 多阶段 standalone 模式照抄 MetaFusion/frontend/Dockerfile（样板），只去掉主仓库前端特有的
# NEXT_PUBLIC_* 构建参数：本应用全部资源与接口都走同源路径，构建期不需要外部地址。
# ==============================================================================
FROM oven/bun:1.4-alpine AS base

FROM base AS deps
WORKDIR /app
# Bun 兼容 npm 锁文件，优先使用 bun.lock
COPY package.json bun.lock* package-lock.json* ./
RUN --mount=type=cache,target=/root/.bun \
    bun install --frozen-lockfile 2>/dev/null || bun install

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
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
