// USBAY-GAME-008 interactive DOM harness (demo-only, read-only).
//
// Reads the rendered /game HTML from stdin, executes its real client-side
// JavaScript inside jsdom, drives the live DOM (toggles, route finder, mode
// filters, navigation) the way a browser would, and emits a JSON report on
// stdout describing the resulting DOM state. The Python test
// (tests/test_game_interactive_dom.py) asserts on that report.
//
// Network (fetch / XHR / WebSocket / EventSource / sendBeacon) and storage
// (localStorage / sessionStorage) are spied on BEFORE any page script runs, so
// the report proves the prototype performs no external calls and persists no
// data while being interacted with.
import { JSDOM, VirtualConsole } from "jsdom";

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
  });
}

const html = await readStdin();

const vc = new VirtualConsole();
vc.on("jsdomError", (e) =>
  process.stderr.write("[jsdomError] " + ((e && e.message) || e) + "\n"),
);

const dom = new JSDOM(html, {
  runScripts: "dangerously",
  url: "http://localhost/game",
  virtualConsole: vc,
  pretendToBeVisual: true,
  beforeParse(window) {
    window.__net = [];
    window.__persist = [];
    window.scrollTo = () => {};
    window.fetch = (...a) => {
      window.__net.push("fetch:" + String(a[0]));
      return Promise.resolve({ ok: true, json: async () => ({}), text: async () => "" });
    };
    window.XMLHttpRequest = function () {};
    window.XMLHttpRequest.prototype.open = function (m, u) {
      window.__net.push("xhr:" + u);
    };
    window.XMLHttpRequest.prototype.send = function () {};
    window.XMLHttpRequest.prototype.setRequestHeader = function () {};
    window.XMLHttpRequest.prototype.addEventListener = function () {};
    window.WebSocket = function (u) {
      window.__net.push("ws:" + u);
    };
    window.WebSocket.prototype.send = function () {};
    window.WebSocket.prototype.close = function () {};
    window.WebSocket.prototype.addEventListener = function () {};
    window.EventSource = function (u) {
      window.__net.push("es:" + u);
    };
    window.EventSource.prototype.close = function () {};
    window.EventSource.prototype.addEventListener = function () {};
    try {
      if (window.navigator) {
        window.navigator.sendBeacon = (u) => {
          window.__net.push("beacon:" + u);
          return true;
        };
      }
    } catch (e) {}
    try {
      const wrap = (store, tag) => {
        if (!store) return;
        const oSet = store.setItem.bind(store);
        store.setItem = (k, v) => {
          window.__persist.push(tag + ".setItem:" + k);
          return oSet(k, v);
        };
        const oRem = store.removeItem.bind(store);
        store.removeItem = (k) => {
          window.__persist.push(tag + ".removeItem:" + k);
          return oRem(k);
        };
        const oClr = store.clear.bind(store);
        store.clear = () => {
          window.__persist.push(tag + ".clear");
          return oClr();
        };
      };
      wrap(window.localStorage, "ls");
      wrap(window.sessionStorage, "ss");
    } catch (e) {}
  },
});

const { window } = dom;
const doc = window.document;
const $ = (s, r) => (r || doc).querySelector(s);
const $$ = (s, r) => Array.from((r || doc).querySelectorAll(s));
const T = (el) => (el ? (el.textContent || "").trim() : "");
const click = (s) => {
  const el = typeof s === "string" ? $(s) : s;
  if (el) el.click();
  return !!el;
};
const nav = (id) => click('[data-nav="' + id + '"]');
const ribbon = () => {
  const r = $(".demo-ribbon");
  return { present: !!r, text: T(r) };
};

const R = {};

// ---- banner at load ----
R.banner = { load: ribbon() };

// ---- route selection + precedence ----
nav("hub");
click('[data-sort="cheapest"]');
R.banner.afterRoute = ribbon().present;

const winners = {};
const badges = {};
["cheapest", "fastest", "xp", "gov"].forEach((k) => {
  click('[data-sort="' + k + '"]');
  winners[k] = T($("#main .trip .rs"));
  badges[k] = T($("#main .bestbadge"));
});
if ($('[data-sort="none"]')) click('[data-sort="none"]');
click('[data-m="all"]');
R.route = {
  winners,
  badges,
  hubModes: Array.from(new Set($$("#tripList .trip .mtag").map(T))),
  tripCount: $$("#tripList .trip").length,
};

// ---- child-safe mode ----
nav("governance");
const fraudBefore = T($('[data-cslabel="Safety Check"]'));
const cs = { toggleExists: !!$("#tgCs") };
cs.bodyBefore = doc.body.classList.contains("cs");
click("#tgCs");
cs.bodyAfter = doc.body.classList.contains("cs");
cs.aria = $("#tgCs") ? $("#tgCs").getAttribute("aria-checked") : null;
cs.fraudBefore = fraudBefore;
cs.fraudAfter = T($('[data-cslabel="Safety Check"]'));
cs.relabeled = cs.fraudBefore !== cs.fraudAfter && cs.fraudAfter.length > 0;
R.banner.afterCs = ribbon().present;
const CTA = [
  "book now", "buy now", "checkout", "add to cart", "pay now", "place order",
  "complete purchase", "confirm booking", "confirm payment", "enter card",
  "card number", "credit card", "cvv",
];
const csText = T(doc.body).toLowerCase();
cs.noBadLang = !CTA.some((p) => csText.includes(p));
click("#tgCs"); // restore canonical wording
R.childSafe = cs;

// ---- accessibility mode ----
const a = { toggleExists: !!$("#tgA11y") };
a.bodyBefore = doc.body.classList.contains("a11y");
click("#tgA11y");
a.bodyAfter = doc.body.classList.contains("a11y");
a.aria = $("#tgA11y") ? $("#tgA11y").getAttribute("aria-checked") : null;
a.controlsReachable =
  !!$("#tgVip") && !!$("#tgCs") && !!$("#tgA11y") && $$("[data-nav]").length > 0;
R.banner.afterA11y = ribbon().present;
R.a11y = a;

// ---- VIP discount per transport mode ----
click("#tgVip");
const vipOn = $("#tgVip") ? $("#tgVip").classList.contains("on") : false;
function firstTripCells() {
  const t = $("#main .trip");
  if (!t) return null;
  const po = $(".po", t),
    pv = $(".pv", t),
    vd = $(".vd", t);
  return {
    po: po ? parseInt(T(po), 10) : null,
    pv: pv ? parseInt(T(pv), 10) : null,
    vd: T(vd),
  };
}
const discount = { vipOn, modes: {} };
nav("hub");
[
  ["air", "air"],
  ["rail", "rail"],
  ["bus", "bus"],
  ["cruise", "cruise"],
  ["ferry", "ferry"],
].forEach(([key, m]) => {
  click('[data-m="' + m + '"]');
  discount.modes[key] = firstTripCells();
});
nav("hotel");
discount.modes.hotel = firstTripCells();
nav("business");
discount.modes.logistics = firstTripCells();
R.discount = discount;

// ---- corpus across all screens: forbidden phrases / unsafe UI ----
const screens = [
  "home", "map", "hub", "rail", "bus", "cruise", "ferry", "airport",
  "hotel", "business", "governance", "crew", "rewards",
];
let corpus = "";
const buttonsAll = [];
const inputsAll = [];
screens.forEach((id) => {
  nav(id);
  corpus += " " + T($("#main"));
  $$('#main button, #main [role="button"]').forEach((b) => buttonsAll.push(T(b)));
  $$("#main input, #main select, #main textarea").forEach((inp) =>
    inputsAll.push({
      tag: inp.tagName,
      type: inp.getAttribute("type"),
      name: inp.getAttribute("name"),
      ph: inp.getAttribute("placeholder"),
    }),
  );
});
$$('header button, header [role="button"]').forEach((b) => buttonsAll.push(T(b)));

const lc = corpus.toLowerCase();
const FORBID = [
  "redeemable for real money", "redeem for real money", "real money",
  "booking confirmed", "payment confirmed", "payment successful",
  "real-world booking", "real booking confirmed", "buy now", "book now",
  "add to cart", "checkout", "pay now", "enter card", "card number", "cvv",
  "credit card",
];
R.forbidden = { found: FORBID.filter((p) => lc.includes(p)) };

nav("rewards");
R.rewardsDisclaimer = T($("#main"))
  .toLowerCase()
  .includes("no monetary value and cannot be purchased or redeemed for anything real");

const BTN_BAD = [
  "book now", "buy now", " buy ", "checkout", "add to cart", "pay now",
  "place order", "complete purchase", "confirm booking", "confirm payment",
  "purchase order",
];
R.unsafe = {
  buttonsBad: buttonsAll.filter((t) => {
    const x = " " + t.toLowerCase() + " ";
    return BTN_BAD.some((p) => x.includes(p));
  }),
  inputs: inputsAll,
  net: window.__net.slice(),
  persist: window.__persist.slice(),
  cookie: doc.cookie,
};

// ---- visual coverage ----
nav("hub");
click('[data-m="all"]');
R.visual = {
  hubModes: Array.from(new Set($$("#tripList .trip .mtag").map(T))),
};
nav("hotel");
R.visual.hotelVisible = $$("#main .trip .mtag").map(T).includes("Hotel");
nav("business");
R.visual.logiVisible = $$("#main .trip .mtag").map(T).includes("Logistics");
nav("crew");
const crewText = T($("#main"));
R.visual.crewThey = crewText.includes("they/them");
R.visual.crewCards = $$("#main .ch").length;
nav("governance");
const govText = T($("#main"));
R.visual.govMissions = ["Policy Vote", "Audit Mission", "Fraud Alert", "Human Review"].filter(
  (m) => govText.includes(m),
);
R.visual.cruiseFerryVisible =
  R.visual.hubModes.includes("Cruise") && R.visual.hubModes.includes("Ferry");

// ---- USBAY-GAME-009R: modes persist across route selection, multi-modal
// selectability, and keyboard reachability of the native button controls ----
function setToggle(sel, want) {
  const el = $(sel);
  if (!el) return false;
  if (el.classList.contains("on") !== want) el.click();
  const now = $(sel);
  return !!now && now.classList.contains("on") === want;
}
const ux = {};

// child-safe stays active after selecting a route
setToggle("#tgCs", true);
nav("hub");
click('[data-sort="cheapest"]');
ux.csActiveAfterRoute = doc.body.classList.contains("cs");
ux.csBannerAfterRoute = ribbon().present;
setToggle("#tgCs", false);

// accessibility stays active after selecting a route
setToggle("#tgA11y", true);
nav("hub");
click('[data-sort="fastest"]');
ux.a11yActiveAfterRoute = doc.body.classList.contains("a11y");
ux.a11yBannerAfterRoute = ribbon().present;
setToggle("#tgA11y", false);

// multi-modal route remains visible and selectable
nav("hub");
const allClicked = click('[data-m="all"]');
const allNow = $('[data-m="all"]');
ux.multiModalClicked = allClicked;
ux.multiModalActive = !!allNow && allNow.classList.contains("active");
ux.multiModalModes = Array.from(new Set($$("#tripList .trip .mtag").map(T)));
ux.multiModalTripCount = $$("#tripList .trip").length;

// keyboard reachability of the native button controls (toggles + nav)
function focusable(el) {
  if (!el) return false;
  const native = ["BUTTON", "A", "INPUT", "SELECT", "TEXTAREA"].indexOf(el.tagName) >= 0;
  const ti = el.getAttribute("tabindex");
  const byTab = ti !== null && parseInt(ti, 10) >= 0;
  if (!(native || byTab)) return false;
  try {
    el.focus();
    return doc.activeElement === el;
  } catch (e) {
    return false;
  }
}
const toggleCtrls = ["#tgVip", "#tgCs", "#tgA11y"].map((s) => $(s));
const navCtrls = $$("[data-nav]");
ux.kbToggles = toggleCtrls.length === 3 && toggleCtrls.every(focusable);
ux.kbNav = navCtrls.length > 0 && navCtrls.every(focusable);
ux.keyboardReachable = ux.kbToggles && ux.kbNav;
R.ux009r = ux;

process.stdout.write(JSON.stringify(R), () => {
  try {
    dom.window.close();
  } catch (e) {}
  process.exit(0);
});
