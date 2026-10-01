import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authErrorText } from "./authErrors";
import zhCN from "../messages/zh-CN.json";
import enUS from "../messages/en-US.json";
import zhTW from "../messages/zh-TW.json";
import jaJP from "../messages/ja-JP.json";

describe("localized authentication errors", () => {
  for (const [locale, messages] of Object.entries({ zhCN, enUS, zhTW, jaJP })) {
    const dict: Record<string, string> = messages;
    const t = (key: string) => dict[key] ?? key;
    for (const [code, key] of Object.entries({
      invalid_credentials: "invalid_credentials",
      username_or_email_taken: "user_already_exists",
      account_banned: "account_disabled",
      banned: "account_disabled",
      invalid_username: "invalid_username",
      invalid_invite_code: "invalid_invite_code",
      registration_closed: "registration_closed",
      login_blocked: "login_blocked",
    })) {
      it(`${locale} translates ${code}`, () => {
        const expected = dict[`auth.error.${key}`];
        assert.ok(expected);
        assert.equal(authErrorText(code, t), expected);
      });
    }
    it(`${locale} translates rate limiting, unavailable service and unknown codes`, () => {
      assert.equal(authErrorText("rate_limited", t, 429), dict["auth.error.rate_limit_exceeded"]);
      assert.equal(authErrorText("upstream", t, 503), dict["auth.error.service_unavailable"]);
      assert.equal(authErrorText("unexpected_private_detail", t), dict["auth.requestFailed"]);
      assert.ok(dict["auth.passwordChangedSignedOut"]);
      assert.ok(dict["auth.sessionsRevokedSignedOut"]);
    });
  }
});
