// The browser name the extension announces when pairing (browser.js).
//
//   node --test extension/test/browser.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

// browser.js reads the extension APIs when loaded.
globalThis.chrome = { runtime: { id: "x", getManifest: () => ({}), getURL: (path) => `chrome-extension://x/${path}` } };
const { detectBrowser } = await import("../browser.js");

const brands = (...names) => ({ userAgentData: { brands: names.map((brand) => ({ brand, version: "142" })) } });

test("the browser is named from its extension URL and brands", () => {
  const chromium = "chrome-extension://pmdlgnpbjfdnmpeadbecmgfoojmocibg/";
  assert.equal(detectBrowser({ firefox: true, url: "moz-extension://a/" }), "Firefox");
  assert.equal(detectBrowser({ url: "moz-extension://a/" }), "Firefox");
  assert.equal(detectBrowser({ url: "webkit-extension://pmdlgnpbjfdnmpeadbecmgfoojmocibg/" }), "Safira");
  assert.equal(detectBrowser({ url: "safari-web-extension://a/" }), "Safari");
  assert.equal(detectBrowser({ url: chromium, navigator: { brave: {}, ...brands("Chromium", "Google Chrome") } }), "Brave");
  assert.equal(detectBrowser({ url: chromium, navigator: brands("Not)A;Brand", "Brave", "Chromium") }), "Brave");
  assert.equal(detectBrowser({ url: chromium, navigator: brands("Chromium", "Google Chrome", "Not_A Brand") }), "Chrome");
  assert.equal(detectBrowser({ url: chromium, navigator: brands("Microsoft Edge", "Chromium") }), "Edge");
  assert.equal(detectBrowser({ url: chromium, navigator: brands("Opera", "Chromium") }), "Opera");
  assert.equal(detectBrowser({ url: chromium, navigator: brands("Chromium") }), "Chromium");
  assert.equal(detectBrowser({ url: chromium }), "Chromium");
  assert.equal(detectBrowser(), "Chromium");
});
