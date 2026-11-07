# Release owner contract — local synthetic implementation

Status: IMPLEMENTED_LOCALLY / SYNTHETIC_VALIDATION_ONLY / NOT_ADOPTED.

Baseline: USJAY77/usbay-policy-brain-public at
dc549b2167dc6bdbe8e5b1c988bb27e9176e388e (tree
b83475115eafe1ca75df661272958f21aac08665).
Local branch: local/release-owner-contract-v1.
Design reference: USBAY-Release-Issuance-Human-Decision-Record.md v1.4.

## Implemented boundary

`governance/release_owner_contract.py` inspects six signed record types:
root, root-signed issuer grant, root-signed owner review policy, issuer request,
owner decision, and independently keyed request-bound authority status.

Exact schemas use domain USBAY_RELEASE_ISSUANCE_NONPRODUCTION_V1 and schema names
usbay.release_owner.<kind>.v1. Record hashes cover the canonical complete signed
envelope. Root, issuer grant, policy and status are independently pinned by a
composition context. Root review requirements and the pinned policy must agree;
the root does not contain a circular hash of its child policy. Parsing rejects
unknown/duplicate fields, floats/non-finite values, oversized envelopes and
unsupported domains. Signatures use existing Ed25519 and canonical-byte
primitives; this is not a replacement for the legacy HMAC release signature.

This initial narrow contract requires one exact tenant/actor/target/tool/resource,
source commit/tree, bundle/core and predecessor hash throughout the chain. Child
validity cannot exceed its parent. Issuance budget is exactly one, re-delegation
is prohibited, and role keys are distinct. Different role keys do not establish
independent humans. This is a conservative proposed role policy, not an adopted
identity/custody decision. No machine role is assigned to the owner by code.

The context must be supplied by trusted composition; it is not parsed from request
JSON. Public keys and provenance hashes in such a context are not proof of actual
adoption. The module reads no environment, files or network, provisions nothing,
and cannot authenticate how an integrating caller obtained the context.

Every public inspection result remains DENY. A valid chain reports
RELEASE_WRITER_UNAVAILABLE with bounded request-hash and deadline evidence;
issuance_authorized and consumption_confirmed remain false. It is not an ALLOW
token and must never be accepted as one. Stale, mismatched, revoked, consumed,
unknown or incomplete inputs yield bounded denial codes without raw payload.

No production/staging fallback or existing threshold change is implemented.
Existing v1 proposal code on the separate preparation branch was not copied or
altered. Gateway, existing release signer/writer, `.replit`, locks and workflows
remain unchanged. The new test file is added to the existing governance tier
mapping; it can run through either unittest or pytest's unittest collection.

## Validation

Targeted command:

```sh
python3 -m unittest tests.test_release_owner_contract -q
```

The initial batch passed 131 unique unittest cases on Linux Python 3.12. This
includes three unchanged artifact-producer behavior checks. Four synthetic
Ed25519 private keys are generated in memory once per test run; none is
serialized, persisted or adopted. No owner private key or password is used.

Cases cover independently pinned chain inputs, signed scope substitutions,
missing scope/records, wrong domains, role/key ambiguity, duplicate JSON,
expiry/validity attenuation, review downgrades, all four authority statuses,
stale/rolled-back status references, replay state and strict environment binding.
The public artifact-test key cannot be substituted for an enrolled release role.
Parallel inspection of 24 requests still produces no permission or consumption;
this is not proof of writer atomicity. Deadline evidence is capped at the status
freshness limit as well as signed validity intervals.

Initial discovery command `python3 -m unittest discover -s tests -p
test_release_owner_contract.py -v` reported 114 passing new cases plus one loader
error: discovery imported the existing tests/helpers package, which attempted
Gateway import and failed immediately because FastAPI was absent. That run was
not PASS. The targeted module command avoids unrelated package discovery. No
dependency was installed and existing helper behavior was not disabled or edited.
The final expanded targeted run passed 131/131. Native pytest, full application,
CI, macOS and live deployment validation were not run.

### Local follow-up review and temporal binding correction

Review reproduced two missing dependency-time checks. Before correction, a
request issued before its bound review policy, or a status statement issued
before its bound owner review, could incorrectly report bindings_valid=true.
All results still remained DENY with issuance_authorized=false; no writer or
operational effect existed. This was a contract-evidence correctness defect,
not demonstrated unauthorized issuance.

The request now obeys both its issuer grant and review policy intervals/issue
times. Status obeys the exact owner review interval/issue time. All dependency
edges are checked transitively back to the root. Four regression cases cover
both ordering defects and the corresponding validity-end broadening cases.

Pre-fix reproduction: 2/2 failed as expected, exit 1, retained at
local-validation-release-owner/review-before-fix.txt. Post-fix targeted suite:
135/135 unique cases passed, exit 0, retained at
local-validation-release-owner/review-after-fix.txt. Initial result.json is
preserved; review-result.json identifies the corrected bytes and evidence hashes.
These local runs do not prove independent human review, live currentness or
writer atomicity. No external publication or operational authority was added.

## Remaining integration gaps

- Adopted root policy, verified issuer/owner/status identities and custody,
  tenant/target selection and real validity/lineage inputs are not provisioned.
- The context pins an observed status. An independent live authority source,
  persistent rollback protection and recheck at protected COMMIT remain absent.
- Active legacy writer integration still lacks the governed nonce/budget,
  source/predecessor CAS and fencing boundary. A separate dormant local writer
  now implements task-owned transactional storage and reconciliation; see
  release-transaction-writer-local-validation.md for exact synthetic evidence.
- The separate writer implements a bounded receipt and a legacy core mapping
  including signed history. See release-writer-native-compatibility.md for
  actual synthetic consumer tests. Runtime integration, production compatibility
  and external publication remain future work. No operational release is issued.
- The artifact producer key keeps its existing test-only scope. Existing release
  HMAC material, root trust and production governance remain unchanged.

These gaps intentionally prevent operational ALLOW. No commit, push, publication,
registry write, workflow dispatch, restart, build, provisioning or deployment was
performed. This branch is a local candidate, not GitHub main or Replit state.
