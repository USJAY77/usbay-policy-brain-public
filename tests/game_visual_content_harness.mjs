// USBAY-GAME-013R visual-content DOM harness (demo-only, read-only).
//
// Reads the rendered /game HTML from stdin, runs its real client-side
// JavaScript inside jsdom, and proves the newly added demo VISUAL content is
// present and safe: an enriched World Map (city nodes incl. New York / London /
// Dubai / Tokyo / Cape Town / Rio / Sydney, multi-modal route lines, status
// tags), travel mission cards, a multi-modal Travel Hub, a Marketplace shell
// with transport-pass + reward-token concept cards (no buy/sell/payment), and
// the demo economy display. Network and storage are spied on before any page
// script runs so the report proves no external calls and no persistence.
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

const dom = new JSDOM(html, {
  runScripts: "dangerously",
  url: "http://localhost/game",
  virtualConsole: vc,
  pretendToBeVisible: true,
  pretendToBeVisual: true,
  beforeParse,
});
const { window } = dom;
const doc = window.document;
const $ = (s, r) => (r || doc).querySelector(s);
const $$ = (s, r) => Array.from((r || doc).querySelectorAll(s));
const T = (el) => (el ? (el.textContent || "").trim() : "");

function gotoHash(id) {
  window.location.hash = id;
  try { window.dispatchEvent(new window.Event("hashchange")); } catch (e) {}
}

const R = {};

// ---- every screen renders with the persistent DEMO banner ----
const navIds = $$("#nav [data-nav]").map((b) => b.dataset.nav);
R.navIds = navIds;
R.everyScreenHasBanner = navIds.every((id) => {
  gotoHash(id);
  return !!$(".demo-ribbon") && T($("#main h1")).length > 0;
});

// ---- World Map: city nodes, route lines, status tags ----
gotoHash("map");
const mapEl = $("#main .map");
const nodeLabels = $$("#main .node .nl").map((n) => T(n));
const cityNames = $$("#main .node").map((n) => (n.getAttribute("data-city") || "").trim());
R.map = {
  present: !!mapEl,
  nodeCount: $$("#main .node").length,
  cities: cityNames,
  routeSvg: !!$("#main .map svg.routes"),
  routeLines: $$("#main .map svg.routes line").length,
  legendStatusTags: $$("#main .map-legend .statustag").map((t) => T(t)),
  nodeStatusTags: $$("#main .node .statustag").map((t) => T(t)),
  summaryText: T($("#main")),
};

// ---- Travel Hub: multi-modal modes + travel mission cards ----
gotoHash("hub");
R.hub = {
  missionCards: $$("#main .mission-card").map((c) => T($("b", c))),
  modePills: $$("#main #modebar *").length,
  tripRows: $$("#main #tripList .trip").length,
  hasMissionsHeading: T($("#main")).toLowerCase().includes("travel missions"),
};

// ---- transport modes visible across the dedicated mode screens ----
const MODE_SCREENS = {
  airport: "flight",
  rail: "train",
  bus: "bus",
  cruise: "cruise",
  ferry: "ferry",
};
R.modes = {};
Object.keys(MODE_SCREENS).forEach((id) => {
  gotoHash(id);
  R.modes[id] = {
    rendered: !!$("#main h1"),
    hasModeTag: $$("#main .mtag").length > 0,
    h1: T($("#main h1")),
  };
});

// ---- Marketplace shell: pass + token concept cards, no buy/sell/payment ----
gotoHash("marketplace");
const mpText = T($("#main")).toLowerCase();
R.marketplace = {
  comingSoon: mpText.includes("coming soon"),
  notImplemented: mpText.includes("not implemented"),
  passCards: $$("#main .pass-card").length,
  tokenCards: $$("#main .token-card").length,
  mainButtons: $$("#main button").length,
  mainInputs: $$("#main input, #main select, #main textarea").length,
  noPaymentWords: !["pay now", "checkout", "add to cart", "card number", "buy now", "sell now"].some((p) => mpText.includes(p)),
  nonRedeemable: mpText.includes("non-redeemable") || mpText.includes("not for sale"),
};

// ---- crew / character cards (diverse roster) ----
gotoHash("crew");
R.crew = { cards: $$("#main .ch").length, hasRoles: $$("#main .ch .cr").length };

// ---- economy display: simulated / non-redeemable VIP marker ----
gotoHash("rewards");
const rwText = T($("#main")).toLowerCase();
R.economy = {
  hasTravel: rwText.includes("travel credits"),
  hasGov: rwText.includes("governance credits"),
  hasXp: rwText.includes("experience"),
  hasAudit: rwText.includes("audit token"),
  vipSimulated: rwText.includes("non-redeemable") || rwText.includes("simulated"),
};

// ---- global safety: no forbidden phrases, no network, no persistence ----
let corpus = "";
navIds.forEach((id) => { gotoHash(id); corpus += " " + T($("#main")); });
const FORBID = [
  "redeemable for real money", "real money", "booking confirmed",
  "payment confirmed", "payment successful", "buy now", "book now",
  "add to cart", "checkout", "pay now", "enter card", "card number", "cvv",
  "credit card",
];
const lc = corpus.toLowerCase();
R.forbidden = FORBID.filter((p) => lc.includes(p));
R.net = window.__net.slice();
R.persist = window.__persist.slice();
R.cookie = doc.cookie;
R.jsErrors = jsErrors.slice();

try { dom.window.close(); } catch (e) {}
process.stdout.write(JSON.stringify(R), () => process.exit(0));
