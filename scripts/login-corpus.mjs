#!/usr/bin/env node
// Records the structure of real sign-in pages for the extension's tests
// (extension/test/corpus/): each page opened in a headless Chrome (its
// JavaScript runs), then only the shape of its forms is kept: the visible
// inputs and their attributes, labels, buttons. No value, no token.
//
//   CHROME=/path/to/chrome-headless-shell node scripts/login-corpus.mjs [site…]
//
// Without sites: every line of extension/test/corpus/sites.txt
// ("name https://…/login"). A recorded page keeps its "expect" block, which
// says what the extension must fill there: it is written by hand, once the
// page has been looked at.
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const corpus = join(root, "extension/test/corpus");
const chrome = process.env.CHROME;
if (!chrome) {
  console.error("CHROME: path to Chrome or chrome-headless-shell");
  process.exit(2);
}

// Runs in the page: the visible inputs of each form (and those outside any
// form), as plain data.
function extract() {
  const visible = (el) => {
    if (el.type === "hidden") return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0) return false;
    const box = el.getBoundingClientRect();
    return box.width > 1 && box.height > 1;
  };
  const text = (s) => (s ?? "").replace(/\s+/g, " ").trim().slice(0, 80);
  const field = (input) => ({
    tag: input.tagName.toLowerCase(),
    type: (input.getAttribute("type") ?? "text").toLowerCase(),
    id: input.id || undefined,
    name: input.getAttribute("name") || undefined,
    autocomplete: input.getAttribute("autocomplete") || undefined,
    placeholder: text(input.getAttribute("placeholder")) || undefined,
    ariaLabel: text(input.getAttribute("aria-label")) || undefined,
    label: text(input.labels?.[0]?.textContent) || undefined,
    inputmode: input.getAttribute("inputmode") || undefined,
    maxlength: input.getAttribute("maxlength") || undefined,
  });
  const buttons = (scope) => [...scope.querySelectorAll("button, input[type=submit], input[type=button]")]
    .filter(visible)
    .map((b) => ({ tag: b.tagName.toLowerCase(), type: (b.getAttribute("type") ?? "").toLowerCase() || undefined, text: text(b.textContent || b.value) }))
    .filter((b) => b.text);
  const inputs = (scope) => [...scope.querySelectorAll("input")]
    .filter((i) => visible(i) && !["submit", "button", "image", "reset", "file"].includes((i.type || "").toLowerCase()))
    .map(field);
  const forms = [...document.forms].map((form) => ({
    id: form.id || undefined,
    name: form.getAttribute("name") || undefined,
    action: (form.getAttribute("action") ?? "").replace(/[?#].*/, "") || undefined,
    inputs: inputs(form),
    buttons: buttons(form),
  })).filter((f) => f.inputs.length);
  const loose = [...document.querySelectorAll("input")].filter((i) => !i.form && visible(i));
  if (loose.length) {
    forms.push({ loose: true, inputs: loose.map(field), buttons: buttons(document).slice(0, 6) });
  }
  return { title: text(document.title), path: location.pathname, forms };
}

async function cdp(port) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("Chrome didn't answer");
}

async function record(url) {
  const profile = mkdtempSync(join(tmpdir(), "verrou-corpus-"));
  const port = 9300 + Math.floor(Math.random() * 500);
  const browser = spawn(chrome, ["--headless", "--disable-gpu", "--no-first-run", `--user-data-dir=${profile}`,
    `--remote-debugging-port=${port}`, "--window-size=1280,900", "about:blank"], { stdio: "ignore" });
  try {
    const socket = new WebSocket(await cdp(port));
    await new Promise((r) => socket.addEventListener("open", r, { once: true }));
    let next = 0;
    const pending = new Map();
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      pending.get(message.id)?.(message);
    });
    const send = (method, params = {}) => new Promise((resolve) => {
      const id = ++next;
      pending.set(id, resolve);
      socket.send(JSON.stringify({ id, method, params }));
    });
    await send("Page.enable");
    await send("Page.navigate", { url });
    // The page's scripts build the form: a few seconds after the load.
    await new Promise((r) => setTimeout(r, 7000));
    const result = await send("Runtime.evaluate", { expression: `(${extract})()`, returnByValue: true });
    socket.close();
    return result.result?.result?.value;
  } finally {
    const exited = new Promise((r) => browser.once("exit", r));
    browser.kill();
    await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
    try { rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {}
  }
}

const lines = readFileSync(join(corpus, "sites.txt"), "utf8").split("\n")
  .map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
  .map((l) => l.split(/\s+/));
const wanted = process.argv.slice(2);
for (const [name, url] of lines.filter(([n]) => !wanted.length || wanted.includes(n))) {
  try {
    const page = await record(url);
    const file = join(corpus, `${name}.json`);
    const kept = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")).expect : undefined;
    writeFileSync(file, JSON.stringify({ name, url, recorded: new Date().toISOString().slice(0, 10), ...page, expect: kept }, null, 2) + "\n");
    console.log(`${name}: ${page.forms.length} form(s), ${page.forms.reduce((n, f) => n + f.inputs.length, 0)} input(s)`);
  } catch (error) {
    console.log(`${name}: ${error.message}`);
  }
}
