// Unit harness for the USBAY game demo governance evidence engine.
// Extracts the engine source (between USBGOV-ENGINE-START/END markers) from
// the /game HTML passed on stdin, evaluates it in isolation (no DOM, no
// network), and prints a JSON result of deterministic checks.
import { readFileSync } from "node:fs";

const html = readFileSync(0, "utf8");
const start = html.indexOf("/*USBGOV-ENGINE-START*/");
const end = html.indexOf("/*USBGOV-ENGINE-END*/");
if (start < 0 || end < 0) {
  console.log(JSON.stringify({ ok: false, error: "engine markers not found" }));
  process.exit(0);
}
const src = html.slice(start, end);
const sandbox = { window: {} };
new Function("window", src)(sandbox.window);
const E = sandbox.window.USBGOV_ENGINE;

const R = { ok: true, checks: {} };
function check(name, cond) { R.checks[name] = !!cond; if (!cond) R.ok = false; }

// deterministic hashing
check("hash_deterministic", E.hash("abc") === E.hash("abc"));
check("hash_8_hex", /^[0-9a-f]{8}$/.test(E.hash("abc")));

// deterministic receipt generation (hash excludes timestamp)
const a = E.create();
const b = E.create();
const ra = a.append({ action: "CHOOSE_ROUTE", target: "t1" });
const rb = b.append({ action: "CHOOSE_ROUTE", target: "t1" });
check("receipt_hash_deterministic", ra.evidenceHash === rb.evidenceHash);
check("genesis_prev", ra.prevHash === E.GENESIS);
check("policy_version", ra.policyVersion === "USBAY-GAME-DEMO-V1");
check("simulation_only_flag", ra.simulationOnly === true);
check("execution_flags_safe",
  ra.executionAuthority === "NOT_GRANTED" &&
  ra.providerCall === "NOT_PERFORMED" &&
  ra.paymentCall === "NOT_PERFORMED");
check("trace_8_steps", Array.isArray(ra.trace) && ra.trace.length === 8);
check("trace_statuses_valid", ra.trace.every(s =>
  ["PASS", "BLOCKED", "NOT_REQUIRED", "NOT_EXECUTED"].includes(s.status)));

// previous-hash chaining + verification
const r2 = a.append({ action: "COMPLETE_MISSION" });
check("chained_prev", r2.prevHash === ra.evidenceHash);
check("verify_valid", a.verify() === "INTEGRITY_VALID");

// blocked receipt keeps execution flags false
const rb2 = a.append({ action: "FAIL_CLOSED_DEMO", decision: "BLOCKED", reasonCode: "CHILD_SAFE_RESTRICTION" });
check("blocked_decision", rb2.decision === "BLOCKED");
check("blocked_reason", rb2.reasonCode === "CHILD_SAFE_RESTRICTION");
check("blocked_flags_safe",
  rb2.executionAuthority === "NOT_GRANTED" &&
  rb2.providerCall === "NOT_PERFORMED" &&
  rb2.paymentCall === "NOT_PERFORMED" &&
  rb2.simulationOnly === true);

// human review simulation
const rr = a.append({ action: "RESTRICTED_DEMO_ACTION", decision: "REVIEW_REQUIRED", reasonCode: "REVIEW_REQUIRED", humanApproval: "PENDING_HUMAN_REVIEW" });
check("review_required", rr.decision === "REVIEW_REQUIRED" && rr.humanApproval === "PENDING_HUMAN_REVIEW");
const rap = a.append({ action: "RESTRICTED_DEMO_ACTION", humanApproval: "APPROVED_SIMULATION_ONLY (" + rr.decisionId + ")" });
check("approval_recorded", rap.humanApproval.startsWith("APPROVED_SIMULATION_ONLY"));
check("approval_never_grants_authority", rap.executionAuthority === "NOT_GRANTED");

// tamper detection + fail-closed
a.receipts[1].requestedTarget = "tampered";
check("tamper_detected", a.verify() === "INTEGRITY_FAILED");
const after = a.append({ action: "CHOOSE_ROUTE" });
check("fail_closed_after_tamper", after && after.blockedByIntegrity === true);

// evidence export
const c = E.create();
c.append({ action: "CLAIM_REWARDS" });
const exp = JSON.parse(c.exportJson());
check("export_labelled_demo", /DEMO EVIDENCE CHAIN/.test(exp.label));
check("export_not_production_assurance", /not cryptographic production assurance/.test(exp.label));
check("export_has_receipts", exp.receipts.length === 1 && exp.integrity === "INTEGRITY_VALID");

// clear resets
c.clear();
check("clear_resets", c.receipts.length === 0 && c.verify() === "INTEGRITY_VALID");

console.log(JSON.stringify(R));
