// A minimal DOM to run content.js in node (vm), without a browser:
// elements, fields, forms, closed shadow DOM, focus, events (capture,
// bubbling, `isTrusted`, retargeting out of the shadow DOM) and the few
// selectors the script needs.

import { readFileSync } from "node:fs";
import vm from "node:vm";

// `i18n` of the extension APIs, in English (extension/_locales/en): the
// tests check the English text. An unknown message name is an error.
const english = JSON.parse(readFileSync(new URL("../_locales/en/messages.json", import.meta.url), "utf8"));

export const i18n = {
  getMessage(name, substitutions = []) {
    const entry = english[name];
    if (!entry) throw new Error(`unknown message: ${name}`);
    const values = [substitutions].flat().map(String);
    const placeholders = Object.fromEntries(Object.entries(entry.placeholders ?? {})
      .map(([key, { content }]) => [key.toLowerCase(), content.replace(/\$(\d)/g, (_, n) => values[n - 1] ?? "")]));
    return entry.message.replace(/\$([A-Za-z0-9_]+)\$/g, (_, key) => placeholders[key.toLowerCase()] ?? "");
  },
  getUILanguage: () => "en",
};

const FOLLOWING = 4;
const PRECEDING = 2;

// Simple selectors, separated by commas: `tag`, `.class`,
// `[attr]`, `[attr=value]`, `tag[attr=value]`.
function matches(element, selector) {
  return selector.split(",").map((part) => part.trim()).some((part) => {
    const match = /^([a-z-]*)(?:\.([\w-]+))?(?:\[([\w-]+)(?:=["']?([^\]"']*)["']?)?\])?$/i.exec(part);
    if (!match) throw new Error(`unsupported selector: ${part}`);
    const [, tag, className, attr, value] = match;
    if (tag && element.tagName !== tag.toUpperCase()) return false;
    if (className && !element.className.split(" ").includes(className)) return false;
    if (attr && value === undefined && element.getAttribute(attr) === null) return false;
    if (attr && value !== undefined && String(element.getAttribute(attr) ?? "").toLowerCase() !== value.toLowerCase()) return false;
    return Boolean(tag || className || attr);
  });
}

export function createDom({ origin = "https://connect.exemple.fr", title = "" } = {}) {
  const url = new URL(origin);
  const document = { listeners: {}, focused: null, readyState: "complete", title };
  const windowListeners = {};

  class FakeEvent {
    constructor(type, init = {}) {
      this.type = type;
      this.bubbles = Boolean(init.bubbles);
      this.composed = Boolean(init.composed);
      this.isTrusted = false;
      this.defaultPrevented = false;
      this.stopped = false;
      Object.assign(this, init.extra ?? {});
    }

    preventDefault() {
      this.defaultPrevented = true;
    }

    stopPropagation() {
      this.stopped = true;
    }

    composedPath() {
      return this.path ?? [];
    }
  }

  class FakeElement {
    constructor(tag) {
      this.tagName = tag.toUpperCase();
      this.children = [];
      this.parent = null;
      this.className = "";
      this.text = "";
      this.listeners = {};
      this.attributes = {};
      this.hidden = false;
      const props = {};
      this.style = {
        setProperty: (name, value, priority) => { props[name] = { value, priority }; },
        getPropertyValue: (name) => props[name]?.value ?? "",
        getPropertyPriority: (name) => props[name]?.priority ?? "",
      };
    }

    set textContent(value) {
      this.text = String(value);
      for (const child of this.children) child.parent = null;
      this.children = [];
    }

    get textContent() {
      return this.text + this.children.map((child) => child.textContent).join("");
    }

    get id() {
      return this.attributes.id ?? "";
    }

    set id(value) {
      this.attributes.id = value;
    }

    get parentNode() {
      return this.parent;
    }

    append(...nodes) {
      for (const node of nodes) {
        node.remove();
        node.parent = this;
        this.children.push(node);
      }
    }

    prepend(...nodes) {
      for (const node of nodes.reverse()) {
        node.remove();
        node.parent = this;
        this.children.unshift(node);
      }
    }

    replaceWith(node) {
      const parent = this.parent;
      if (!parent) return;
      node.remove();
      parent.children.splice(parent.children.indexOf(this), 1, node);
      node.parent = parent;
      this.parent = null;
    }

    remove() {
      if (!this.parent) return;
      this.parent.children.splice(this.parent.children.indexOf(this), 1);
      this.parent = null;
    }

    // The root: the document, or a shadow DOM root (with its host).
    get rootNode() {
      let node = this;
      while (node.parent) node = node.parent;
      return node;
    }

    getRootNode() {
      return this.rootNode;
    }

    get isConnected() {
      const root = this.rootNode;
      return root === document.documentElement || Boolean(root.host?.isConnected);
    }

    getAttribute(name) {
      return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null;
    }

    setAttribute(name, value) {
      this.attributes[name] = String(value);
    }

    addEventListener(type, listener, capture = false) {
      (this.listeners[type] ??= []).push({ listener, capture: Boolean(capture) });
    }

    dispatchEvent(event) {
      dispatch(this, event);
      return !event.defaultPrevented;
    }

    attachShadow({ mode }) {
      this.shadow = new FakeElement("#shadow-root");
      this.shadow.host = this;
      this.shadow.mode = mode;
      Object.defineProperty(this.shadow, "activeElement", {
        get: () => {
          const focused = document.focused;
          return focused && focused.rootNode === this.shadow ? focused : null;
        },
      });
      // Closed: the page has no access to it.
      this.shadowRoot = mode === "open" ? this.shadow : null;
      return this.shadow;
    }

    *walk() {
      for (const child of this.children) {
        yield child;
        yield* child.walk();
      }
    }

    querySelectorAll(selector) {
      return [...this.walk()].filter((node) => matches(node, selector));
    }

    querySelector(selector) {
      return this.querySelectorAll(selector)[0] ?? null;
    }

    contains(other) {
      for (let node = other; node; node = node.parent) if (node === this) return true;
      return false;
    }

    closest(selector) {
      for (let node = this; node && node.tagName; node = node.parent) if (matches(node, selector)) return node;
      return null;
    }

    getBoundingClientRect() {
      const index = order().indexOf(this);
      const shown = !this.hidden && !this.closestHidden();
      const top = 100 + index * 40;
      return shown
        ? { left: 50, top, right: 350, bottom: top + 30, width: 300, height: 30 }
        : { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
    }

    closestHidden() {
      for (let node = this.parent; node && node.tagName; node = node.parent) if (node.hidden) return true;
      return false;
    }

    compareDocumentPosition(other) {
      const list = order();
      const a = list.indexOf(this);
      const b = list.indexOf(other);
      return b > a ? FOLLOWING : PRECEDING;
    }

    focus() {
      setFocus(this);
    }

    blur() {
      if (document.focused === this) setFocus(null);
    }

    click() {
      // `element.click()` from the page: never a real click.
      dispatch(this, new FakeEvent("click", { bubbles: true, composed: true }));
    }
  }

  // Value of the fields: on the prototype, like the real one (content.js
  // goes through its descriptor to imitate typing).
  class FakeInput extends FakeElement {
    constructor() {
      super("input");
      this.current = "";
      this.disabled = false;
      this.readOnly = false;
      this.maxLength = -1;
      this.inputMode = "";
    }

    get value() {
      return this.current;
    }

    set value(value) {
      this.current = String(value);
    }

    get name() {
      return this.attributes.name ?? "";
    }

    get placeholder() {
      return this.attributes.placeholder ?? "";
    }

    get autocomplete() {
      return this.attributes.autocomplete ?? "";
    }

    get form() {
      return this.closest("form");
    }

    // <label for="id">, or a <label> around the field.
    get labels() {
      let top = this;
      while (top.parent) top = top.parent;
      return [...top.walk()].filter((node) => node.tagName === "LABEL"
        && ((this.id && node.attributes.for === this.id) || node.contains(this)));
    }
  }

  class FakeSelect extends FakeElement {
    constructor() {
      super("select");
      this.disabled = false;
      this.options = [];
      this.value = "";
    }
  }

  class FakeButton extends FakeElement {
    constructor() {
      super("button");
      this.disabled = false;
    }

    get value() {
      return "";
    }

    get form() {
      return this.closest("form");
    }
  }

  // `requestSubmit(submitter)`: like the browser, refuses a button that
  // doesn't submit this form, then emits "submit" (with `submitter`).
  // `submissions` keeps each submission.
  class FakeForm extends FakeElement {
    constructor() {
      super("form");
      this.submissions = [];
    }

    requestSubmit(submitter = null) {
      if (submitter) {
        const type = (submitter.getAttribute("type") ?? "submit").toLowerCase();
        if (type !== "submit") throw new TypeError("not a submit button");
        if (submitter.form !== this) throw new Error("NotFoundError");
      }
      const event = new FakeEvent("submit", { bubbles: true, extra: { submitter } });
      dispatch(this, event);
      if (!event.defaultPrevented) this.submissions.push({ submitter });
    }
  }

  // Document order (shadow DOM included, after the host).
  function order() {
    const out = [];
    const walk = (node) => {
      out.push(node);
      for (const child of node.children) walk(child);
      if (node.shadow) walk(node.shadow);
    };
    walk(document.documentElement);
    return out;
  }

  // The event's path: from the node to the document, leaving shadow DOMs
  // through their host; seen from beyond a host, the target is the host.
  function dispatch(target, event) {
    const path = [];
    for (let node = target; node; node = node.parent ?? node.host) path.push(node);
    path.push(document, context);
    event.path = path;
    const targets = new Map();
    let seen = target;
    for (const node of path) {
      targets.set(node, seen);
      if (node.host) seen = node.host;
    }
    const call = (node, capture) => {
      const listeners = node === document ? document.listeners : node === context ? windowListeners : node.listeners;
      for (const { listener, capture: phase } of [...(listeners[event.type] ?? [])]) {
        if (phase !== capture || event.stopped) continue;
        event.target = targets.get(node);
        event.currentTarget = node;
        listener(event);
      }
    };
    for (const node of [...path].reverse()) {
      if (event.stopped) return;
      if (node !== target) call(node, true);
    }
    call(target, true);
    call(target, false);
    if (!event.bubbles) return;
    for (const node of path.slice(1)) {
      if (event.stopped) return;
      call(node, false);
    }
  }

  function setFocus(element) {
    const previous = document.focused;
    if (previous === element) return;
    document.focused = element;
    if (previous) dispatch(previous, new FakeEvent("focusout", { bubbles: true, composed: true }));
    if (element) dispatch(element, new FakeEvent("focusin", { bubbles: true, composed: true }));
  }

  document.documentElement = new FakeElement("html");
  document.body = new FakeElement("body");
  document.documentElement.append(document.body);
  document.createElement = (tag) => {
    const name = tag.toLowerCase();
    if (name === "input") return new FakeInput();
    if (name === "select") return new FakeSelect();
    if (name === "button") return new FakeButton();
    if (name === "form") return new FakeForm();
    return new FakeElement(name);
  };
  // SVG (Verrou's icon): an ordinary element is enough here.
  document.createElementNS = (_ns, tag) => new FakeElement(tag);
  document.querySelectorAll = (selector) => document.documentElement.querySelectorAll(selector);
  document.querySelector = (selector) => document.documentElement.querySelector(selector);
  document.addEventListener = (type, listener, capture = false) => {
    (document.listeners[type] ??= []).push({ listener, capture: Boolean(capture) });
  };
  // The focus, seen from the page: the host when it is in a shadow DOM.
  Object.defineProperty(document, "activeElement", {
    get: () => {
      let node = document.focused;
      while (node && node.rootNode.host) node = node.rootNode.host;
      return node ?? document.body;
    },
  });

  // Mutation observers: triggered by hand by the tests.
  const observers = [];
  class FakeMutationObserver {
    constructor(callback) {
      this.callback = callback;
      this.active = false;
      observers.push(this);
    }

    observe() {
      this.active = true;
    }

    disconnect() {
      this.active = false;
    }
  }

  const context = {
    document,
    location: { origin: url.origin, hostname: url.hostname, href: url.href, pathname: url.pathname },
    HTMLInputElement: FakeInput,
    HTMLSelectElement: FakeSelect,
    HTMLFormElement: FakeForm,
    Element: FakeElement,
    Node: { DOCUMENT_POSITION_FOLLOWING: FOLLOWING, DOCUMENT_POSITION_PRECEDING: PRECEDING },
    Event: FakeEvent,
    MutationObserver: FakeMutationObserver,
    getComputedStyle: () => ({ visibility: "visible", display: "block", opacity: "1" }),
    setTimeout, clearTimeout, setInterval, clearInterval, Promise, console, crypto, Uint32Array,
    scrollX: 0, scrollY: 0,
    addEventListener: (type, listener, capture = false) => {
      (windowListeners[type] ??= []).push({ listener, capture: Boolean(capture) });
    },
  };
  context.window = context;
  context.top = context;
  context.globalThis = context;
  vm.createContext(context);

  // Builds an element: `h("input", { type: "password" })`.
  function h(tag, attributes = {}, ...children) {
    const element = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes)) {
      if (name === "value") element.value = value;
      else if (name === "hidden") element.hidden = value;
      else if (name === "class") element.className = value;
      else if (name === "maxLength" || name === "disabled") element[name] = value;
      else element.setAttribute(name, value);
    }
    for (const child of children) {
      if (typeof child === "string") element.text += child;
      else element.append(child);
    }
    return element;
  }

  // A real event (`isTrusted`) or one from the page.
  function fire(target, type, { trusted = true, ...extra } = {}) {
    const event = new FakeEvent(type, { bubbles: true, composed: true, extra });
    event.isTrusted = trusted;
    dispatch(target, event);
    return event;
  }

  function mutate(target = document.body) {
    for (const observer of observers) {
      if (observer.active) observer.callback([{ type: "childList", target, addedNodes: [...target.children], removedNodes: [] }]);
    }
  }

  return { context, document, h, fire, mutate, run: (code) => vm.runInContext(code, context) };
}
