"use client";

// 实例设置的**可写契约**与纯函数：页面（校验/提交）与字段组件（渲染）共用这一份。
//
// 判据只有一条——**服务端接受写入、且仓库里真有代码消费**：
//   可配置 = WRITABLE；服务端接受但无人消费的键 = UNWRITABLE_REASON（只展示，不给输入框）。
// 判据来源：internal/store/access.go 的 UpdateSettings 接受表 + 各消费点。
// 这里不解释权限码含义，也不维护"服务端会返回哪些键"的第二份清单：
// 键永远来自 GET /api/admin/settings 本身，本表只回答"这个键该不该给输入框"。

export type Control = "boolean" | "number" | "stringArray";

export interface FieldSpec {
  control: Control;
  /** high：改它影响"谁能进来 / 认证端点的防护强度"，保存前必须过一次二次确认。 */
  impact: "high" | "tune";
}

/**
 * 可配置项清单（= 服务端接受表 ∩ 真有消费点），每条的消费点：
 *
 *   registration_enabled        → store.Register：关闭即 registration_closed（groups.go）
 *   invite_required             → Register 事务里的 consumeInvite（groups.go）
 *   auth_rate_limit_enabled     → Store.RateLimitPolicy → 认证写入限流中间件（access.go / handler.go）
 *   auth_rate_limit_per_minute  → 同上
 *   registration_default_groups → Register 给新账号建组成员关系（groups.go）
 */
export const WRITABLE: Record<string, FieldSpec> = {
  registration_enabled: { control: "boolean", impact: "high" },
  invite_required: { control: "boolean", impact: "high" },
  auth_rate_limit_enabled: { control: "boolean", impact: "high" },
  auth_rate_limit_per_minute: { control: "number", impact: "tune" },
  registration_default_groups: { control: "stringArray", impact: "high" },
};

/** 限流速率的合法区间，与服务端 UpdateSettings 的校验同口径。 */
export const RATE_LIMIT_MIN = 1;
export const RATE_LIMIT_MAX = 100000;

/** 提交前要二次确认的键（影响准入/防护）。 */
export const HIGH_IMPACT_KEYS = Object.keys(WRITABLE).filter((key) => WRITABLE[key]?.impact === "high");

/** 调低限流速率同样削弱防爆破、调得过低还会挡住正常登录，按高影响项对待。 */
export const RATE_LIMIT_KEY = "auth_rate_limit_per_minute";

/**
 * 服务端**接受写入但无人消费**的键：只读展示，并写明查证结论。
 * 给它们做输入框等于让管理员改一个不生效的字段。
 *
 * 目前只剩 require_email_verification（邮件通道未接入，唯一读它的是主站登录页的一句提示）。
 * 曾经的 site_name 已由账号服务退役（写它 invalid_setting、读面也不再回传），所以这里不留条目；
 * 未登记的未知键按 instance.why.unknown 渲染，同样只展示、不给输入框。
 */
export const UNWRITABLE_REASON: Record<string, string> = {
  require_email_verification: "instance.why.require_email_verification",
};

/** 控件的"原始形态"：布尔控件是 boolean，数字与组码控件是字符串。 */
export type RawValue = string | boolean;
export type Edits = Record<string, RawValue>;

/** 校验失败的键与参数：翻译在页面里做，纯函数不碰 i18n。 */
export interface FieldError {
  key: string;
  vars?: Record<string, string | number>;
}

export function parseCodes(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/** 服务端值 → 控件原始形态；用它判断"这一项到底改了没有"。 */
export function rawForm(value: unknown, spec: FieldSpec): RawValue {
  if (spec.control === "boolean") return value === true;
  if (spec.control === "number") return typeof value === "number" ? String(value) : "";
  return Array.isArray(value) ? (value as unknown[]).map(String).join("\n") : "";
}

/** 控件原始形态 → 提交值；调用前已通过 validatePending，数字与数组不会再出意外。 */
export function submitValue(raw: RawValue, spec: FieldSpec): unknown {
  if (spec.control === "boolean") return raw === true;
  if (spec.control === "number") return Number.parseInt(String(raw), 10);
  return parseCodes(String(raw));
}

/** 只读展示与二次确认用：把服务端值翻成人能读的一行。 */
export function describeValue(value: unknown, t: (key: string) => string): string {
  if (typeof value === "boolean") return value ? t("instance.boolTrue") : t("instance.boolFalse");
  if (Array.isArray(value)) return (value as unknown[]).map(String).join("、");
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

/** 只读展示的控件种类：只看值的实际类型，不看键名。 */
export function valueKind(value: unknown): Control | "string" | "json" {
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return "stringArray";
  return "json";
}

/** 组码格式与服务端 ValidGroupCode 同口径（access.go：^[a-z][a-z0-9_-]{1,63}$）。 */
export const GROUP_CODE_RE = /^[a-z][a-z0-9_-]{1,63}$/;

/**
 * 客户端校验：只拦"服务端必然拒绝"或"服务端会静默忽略"的输入。
 * 最后一条尤其重要——注册时对不存在的组是**静默跳过**（groups.go 的 continue），
 * 放一个不存在的组码过去等于让人白改一次设置。
 */
export function validatePending(pending: string[], edits: Edits, knownGroupCodes: string[]): FieldError | null {
  for (const key of pending) {
    const spec = WRITABLE[key];
    if (!spec) continue;
    const raw = edits[key];
    if (spec.control === "number") {
      const text = String(raw ?? "").trim();
      const num = Number.parseInt(text, 10);
      if (!/^\d+$/.test(text) || Number.isNaN(num) || num < RATE_LIMIT_MIN || num > RATE_LIMIT_MAX) {
        return { key: "instance.err.rateLimitRange", vars: { min: RATE_LIMIT_MIN, max: RATE_LIMIT_MAX } };
      }
    }
    if (spec.control === "stringArray") {
      for (const code of parseCodes(String(raw ?? ""))) {
        if (!GROUP_CODE_RE.test(code)) return { key: "instance.err.groupsFormat", vars: { code } };
        // 组清单要 auth.groups.manage 才拿得到；拿不到时只校验格式，界面会如实说明"无法确认存在性"。
        if (knownGroupCodes.length > 0 && !knownGroupCodes.includes(code)) {
          return { key: "instance.err.groupsUnknown", vars: { code } };
        }
      }
    }
  }
  return null;
}

/** 这次提交是否把限流速率调低了。 */
export function isLoweringRateLimit(pending: string[], edits: Edits, current: unknown): boolean {
  if (!pending.includes(RATE_LIMIT_KEY)) return false;
  const next = Number.parseInt(String(edits[RATE_LIMIT_KEY] ?? ""), 10);
  const before = Number.parseInt(String(current ?? ""), 10);
  if (Number.isNaN(next) || Number.isNaN(before)) return true;
  return next < before;
}
