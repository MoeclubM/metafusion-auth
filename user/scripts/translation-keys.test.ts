import assert from "node:assert/strict";
import { it } from "node:test";
import { translationKeys } from "./translation-keys.mjs";

it("extracts literal calls and runtime-selected auth messages without permission codes", () => {
  const keys = translationKeys(`
    t("nav.login"); t('auth.username');
    const errors = { invalid_credentials: "auth.error.invalid_credentials" };
    const notice = "auth.passwordChangedSignedOut";
    const permission = "auth.users.manage";
  `);
  assert.deepEqual(Array.from(keys).sort(), ["nav.login", "auth.username", "auth.error.invalid_credentials", "auth.passwordChangedSignedOut"].sort());
});
