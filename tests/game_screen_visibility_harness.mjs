// USBAY-GAME-012R screen-visibility DOM harness (demo-only, read-only).
//
// Reads the rendered /game HTML from stdin, runs its real client-side
// JavaScript inside jsdom, and proves that every implemented screen is
// reviewable via the visible selector and via per-screen hash deep-links
// (/game#home, /game#rail, ...). For each screen it records the active
// selector entry, the rendered heading, demo-banner presence, and whether
// any booking/payment controls or form inputs appear. Network and storage
// are spied on before any page script runs so the report proves the
// prototype performs no external calls and persists no data.
function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
  });
}

const html = await readStdin();
const { JSDOM, VirtualConsole } = await import("jsdom");

const vc = new VirtualConsole();
const jsErrors = [];
vc.on("jsdomError", (e) => jsErrors.push((e && e.message) || String(e)));

function beforeParse(window) {
  window.__net = [];
  window.__persist = [];
  window.scrollTo = () => {};
  window.fetch = (...a) => {
    window.__net.push("fetch:" + String(a[0]));
    return Promise.resolve({ ok: true, json: async () => ({}), text: async () => "" });
  };
  window.XMLHttpRequest = function () {};
  window.XMLHttpRequest.prototype.open = function (m, u) { window.__net.push("xhr:" + u); };
  window.XMLHttpRequest.prototype.send = function () {};
  window.XMLHttpRequest.prototype.setRequestHeader = function () {};
  window.XMLHttpRequest.prototype.addEventListener = function () {};
  window.WebSocket = function (u) { window.__net.push("ws:" + u); };
  window.WebSocket.prototype.send = function () {};
  window.WebSocket.prototype.close = function () {};
  window.WebSocket.prototype.addEventListener = function () {};
  window.EventSource = function (u) { window.__net.push("es:" + u); };
  window.EventSource.prototype.close = function () {};
  window.EventSource.prototype.addEventListener = function () {};
  try {
    if (window.navigator) {
      window.navigator.sendBeacon = (u) => { window.__net.push("beacon:" + u); return true; };
    }
  } catch (e) {}
  try {
    const wrap = (store, tag) => {
      if (!store) return;
      const oSet = store.setItem.bind(store);
      store.setItem = (k, v) => { window.__persist.push(tag + ".setItem:" + k); return oSet(k, v); };
      const oRem = store.removeItem.bind(store);
      store.removeItem = (k) => { window.__persist.push(tag + ".removeItem:" + k); return oRem(k); };
      const oClr = store.clear.bind(store);
      store.clear = () => { window.__persist.push(tag + ".clear"); return oClr(); };
    };
    wrap(window.localStorage, "ls");
    wrap(window.sessionStorage, "ss");
  } catch (e) {}
}

function makeDom(url) {
  return new JSDOM(html, {
    runScripts: "dangerously",
    url,
    virtualConsole: vc,
    pretendToBeVisible: true,
    pretendToBeVisual: true,
    beforeParse,
  });
}

const BTN_BAD = [
  "book now", "buy now", " buy ", "checkout", "add to cart", "pay now",
  "place order", "complete purchase", "confirm booking", "confirm payment",
  "purchase order", "sell now", "add funds", "top up", "enter card",
  "card number", "credit card", "cvv",
];

const dom = makeDom("http://localhost/game");
const { window } = dom;
const doc = window.document;
const $ = (s, r) => (r || doc).querySelector(s);
const $$ = (s, r) => Array.from((r || doc).querySelectorAll(s));
const T = (el) => (el ? (el.textContent || "").trim() : "");

const R = {};

// ---- selector: every screen is listed in the visible nav ----
const navBtns = $$("#nav [data-nav]");
R.selector = {
  navCount: navBtns.length,
  navIds: navBtns.map((b) => b.dataset.nav),
  navLabels: navBtns.map((b) => T(b)),
  allButtons: navBtns.every((b) => b.tagName === "BUTTON"),
  allFocusable: navBtns.every((b) => {
    try { b.focus(); return doc.activeElement === b; } catch (e) { return false; }
  }),
};

// ---- keyboard navigation across the selector (ArrowDown moves focus) ----
let kbMoved = false;
try {
  if (navBtns.length > 1) {
    navBtns[0].focus();
    const ev = new window.KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true });
    navBtns[0].dispatchEvent(ev);
    kbMoved = doc.activeElement === navBtns[1];
  }
} catch (e) {}
R.selector.keyboardMovesFocus = kbMoved;

// ---- deep-link routing: drive each screen via location.hash ----
function gotoHash(id) {
  window.location.hash = id;
  try { window.dispatchEvent(new window.Event("hashchange")); } catch (e) {}
}
function activeNavId() {
  const a = $("#nav [data-nav].active");
  return a ? a.dataset.nav : null;
}
function mainBadButtons() {
  return $$('#main button, #main [role="button"]')
    .map(T)
    .filter((t) => {
      const x = " " + t.toLowerCase() + " ";
      return BTN_BAD.some((p) => x.includes(p));
    });
}

R.screens = R.selector.navIds.map((id) => {
  gotoHash(id);
  return {
    id,
    activeNav: activeNavId(),
    ariaCurrent: (() => { const a = $('#nav [data-nav="' + id + '"]'); return a ? a.getAttribute("aria-current") : null; })(),
    h1: T($("#main h1")),
    crumb: T($("#main .crumb")),
    bannerPresent: !!$(".demo-ribbon"),
    bannerText: T($(".demo-ribbon")),
    mainInputs: $$("#main input, #main select, #main textarea").length,
    mainBadButtons: mainBadButtons(),
  };
});

// ---- marketplace placeholder specifics ----
gotoHash("marketplace");
const mpText = T($("#main")).toLowerCase();
R.marketplace = {
  present: R.selector.navIds.indexOf("marketplace") >= 0,
  h1: T($("#main h1")),
  comingSoon: mpText.includes("coming soon"),
  notImplemented: mpText.includes("not implemented"),
  noBuying: !mpText.includes("buy") || mpText.includes("no buying"),
  noPaymentWords: !["pay now", "checkout", "add to cart", "card number"].some((p) => mpText.includes(p)),
  mainInputs: $$("#main input, #main select, #main textarea").length,
  mainButtons: $$("#main button").length,
};

// ---- global safety: forbidden phrases across every screen corpus ----
let corpus = "";
R.selector.navIds.forEach((id) => { gotoHash(id); corpus += " " + T($("#main")); });
const FORBID = [
  "redeemable for real money", "real money", "booking confirmed",
  "payment confirmed", "payment successful", "buy now", "book now",
  "add to cart", "checkout", "pay now", "enter card", "card number", "cvv",
  "credit card",
];
const lc = corpus.toLowerCase();
R.forbidden = FORBID.filter((p) => lc.includes(p));

// ---- network / persistence / cookies ----
R.net = window.__net.slice();
R.persist = window.__persist.slice();
R.cookie = doc.cookie;
R.jsErrors = jsErrors.slice();

// ---- initial-hash boot: loading /game#governance lands on Governance ----
try {
  const dom2 = makeDom("http://localhost/game#governance");
  const doc2 = dom2.window.document;
  R.initialHash = {
    requested: "governance",
    h1: T(doc2.querySelector("#main h1")),
    activeNav: (() => { const a = doc2.querySelector("#nav [data-nav].active"); return a ? a.dataset.nav : null; })(),
  };
  try { dom2.window.close(); } catch (e) {}
} catch (e) {
  R.initialHash = { error: String(e) };
}

try { dom.window.close(); } catch (e) {}
process.stdout.write(JSON.stringify(R), () => process.exit(0));
