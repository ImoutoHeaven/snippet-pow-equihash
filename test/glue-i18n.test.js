import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const makeElement = () => ({
  style: { setProperty() {} },
  classList: { add() {}, remove() {} },
  appendChild() {},
  addEventListener() {},
  remove() {},
  innerHTML: "",
  textContent: "",
});

globalThis.document = {
  title: "",
  head: makeElement(),
  documentElement: makeElement(),
  body: { ...makeElement(), style: { setProperty() {} } },
  createElement: () => makeElement(),
  getElementById: () => makeElement(),
  querySelectorAll: () => [],
  addEventListener() {},
};
globalThis.window = {
  location: { href: "https://example.com/", replace() {}, reload() {} },
  parent: null,
  opener: null,
  innerWidth: 1200,
  innerHeight: 800,
};
globalThis.window.parent = globalThis.window;
Object.defineProperty(globalThis, "navigator", {
  value: { languages: ["en-US"], language: "en-US" },
  configurable: true,
});
globalThis.setTimeout = () => 0;
globalThis.requestAnimationFrame = () => 0;

const root = fileURLToPath(new URL("..", import.meta.url));
const glue = await import(`${pathToFileURL(join(root, "glue.js")).href}?v=${Date.now()}`);

test("resolveLocale selects supported languages and falls back to English", () => {
  assert.equal(glue.resolveLocale(["zh-CN", "en-US"]), "zh");
  assert.equal(glue.resolveLocale(["zh-TW", "en-US"]), "zh_hant");
  assert.equal(glue.resolveLocale(["zh-HK"]), "zh_hant");
  assert.equal(glue.resolveLocale(["ja-JP", "en-US"]), "ja");
  assert.equal(glue.resolveLocale(["ko-KR", "en-US"]), "ko");
  assert.equal(glue.resolveLocale(["fr-FR"]), "fr");
  assert.equal(glue.resolveLocale(["es-ES"]), "en");
});

test("translate returns localized text and formats variables", () => {
  assert.equal(glue.translate("zh", "title_verifying"), "验证中...");
  assert.equal(glue.translate("zh_hant", "title_verifying"), "驗證中...");
  assert.equal(glue.translate("ja", "title_verifying"), "確認中...");
  assert.equal(glue.translate("ko", "title_verifying"), "확인 중...");
  assert.equal(glue.translate("fr", "title_verifying"), "Vérification...");
  assert.equal(glue.translate("en", "connection_retry", { ms: 500 }), "Connection error. Retrying in 500ms...");
  assert.equal(glue.translate("fr", "connection_retry", { ms: 500 }), "Erreur de connexion. Nouvelle tentative dans 500ms...");
  assert.equal(glue.translate("ja", "missing_key"), "missing_key");
});
