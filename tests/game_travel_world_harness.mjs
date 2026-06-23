// USBAY-GAME-014 travel-world landing DOM harness (demo-only, read-only).
//
// Reads the rendered /game HTML from stdin, runs its real client-side
// JavaScript inside jsdom with NO initial hash, and proves the travel-first
// landing experience: the World Map is the default landing screen, a visible
// travel navigation (Flights/Trains/Buses/Cruises/Ferries/Hotels/Logistics) is
// present, world destination cards (New York/London/Dubai/Tokyo/Cape Town/Rio/
// Sydney) render, a transport selection panel exists, the Governance Center is
// still reachable behind its own navigation, Academy/Rewards/Crew/Profile stay
// accessible, the DEMO banner shows on every screen, and there are no
// booking/payment controls, no network calls and no persistence.
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

// Boot with NO hash so we can observe the default landing screen.
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

// ---- default landing: World Map loads with no hash ----
const activeNav = $("#nav [data-nav].active");
R.defaultLanding = {
  activeNavId: activeNav ? activeNav.dataset.nav : null,
  h1: T($("#main h1")),
  hasMap: !!$("#main .map"),
  hasTravelNav: !!$("#main #travelnav"),
};

// ---- visible travel navigation on the landing ----
const travelNavLabels = $$("#main #travelnav .tnav").map((b) => T(b));
R.travelNav = {
  count: travelNavLabels.length,
  labels: travelNavLabels,
  hasAll: ["Flights", "Trains", "Buses", "Cruises", "Ferries", "Hotels", "Logistics"]
    .every((l) => travelNavLabels.includes(l)),
};

// ---- transport selection panel ----
R.transportPanel = {
  present: !!$("#main #transportSel"),
  cards: $$("#main #transportSel .card").length,
};

// ---- world destination cards ----
const destText = T($("#main #destCards")).toLowerCase();
R.destinations = {
  present: !!$("#main #destCards"),
  cards: $$("#main #destCards .dest-card").length,
  hasAllCities: ["new york", "london", "dubai", "tokyo", "cape town", "rio", "sydney"]
    .every((c) => destText.includes(c)),
};

// ---- route visualization on the map ----
R.routes = {
  svg: !!$("#main .map svg.routes"),
  lines: $$("#main .map svg.routes line").length,
  legend: !!$("#main .map-legend"),
};

// ---- Governance Center accessible behind its own navigation ----
const govNavIds = $$("#nav [data-nav]").map((b) => b.dataset.nav);
R.governance = { inNav: govNavIds.includes("governance") };
gotoHash("governance");
R.governance.renders = !!$("#main h1");
R.governance.h1 = T($("#main h1"));

// ---- Academy / Rewards / Crew / Profile stay accessible ----
R.coreScreens = {};
["academy", "rewards", "crew", "profile"].forEach((id) => {
  R.coreScreens[id] = { inNav: govNavIds.includes(id) };
  gotoHash(id);
  R.coreScreens[id].renders = !!$("#main h1");
});

// ---- DEMO banner on every screen ----
const navIds = $$("#nav [data-nav]").map((b) => b.dataset.nav);
R.navIds = navIds;
R.everyScreenHasBanner = navIds.every((id) => {
  gotoHash(id);
  return !!$(".demo-ribbon") && T($("#main h1")).length > 0;
});

// ---- global safety: no booking/payment controls, no net, no persistence ----
let corpus = "";
let totalInputs = 0;
navIds.forEach((id) => {
  gotoHash(id);
  corpus += " " + T($("#main"));
  totalInputs += $$("#main input, #main select, #main textarea").length;
});
const FORBID = [
  "redeemable for real money", "real money", "booking confirmed",
  "payment confirmed", "payment successful", "buy now", "book now",
  "add to cart", "checkout", "pay now", "enter card", "card number", "cvv",
  "credit card",
];
const lc = corpus.toLowerCase();
R.forbidden = FORBID.filter((p) => lc.includes(p));
R.totalInputs = totalInputs;
R.net = window.__net.slice();
R.persist = window.__persist.slice();
R.cookie = doc.cookie;
R.jsErrors = jsErrors.slice();

try { dom.window.close(); } catch (e) {}
process.stdout.write(JSON.stringify(R), () => process.exit(0));
