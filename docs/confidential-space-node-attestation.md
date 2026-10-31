# Disabled Confidential Space node-attestation candidate

This is a local implementation candidate with synthetic tests. It has not been
deployed into Confidential Space or validated against Google-signed evidence.
No PB identifier, human approval, enrollment or operational activation is implied.
EGAP-HYDRA-REMOTE-TRANSPORT-AUTH remains OPEN.

## Connected workload and verifier boundary

The intended measured workload is the complete approved USBAY Gateway/node
producer container, including its request validation and worker code. Both the
in-process node and its subprocess worker must run inside that measured boundary.
A token from a separate attestation sidecar cannot endorse a Mac/Replit response.
The adapter uses the documented launcher UDS `/run/container_launcher/teeserver.sock`,
POST `/v1/token`, `token_type=OIDC`, a workload-configured audience, and one nonce.
No direct metadata/Google API, discovery, key-URL or automatic JWKS fetch is present.

The Gateway supplies its original signed request transiently to the opted-in
local producer. The worker independently verifies that signature with the existing
request-key contract, recomputes its canonical request hash and checks tenant,
nonce, policy version and request freshness. The remote-client serialization
strips this private local field in both existing remote client families. It is not
included in audit/diagnostic output. Mixed live-backend/adapter configuration is
unsupported and fails closed; only the local in-process/worker route is integrated.

The producer constructs the immutable `HydraNodeDecision` itself using the
existing in-process policy result. Its API accepts no response or response-hash.
Its token nonce is SHA-256 of canonical JSON containing domain
`USBAY/ConfidentialSpace/NodeResponse/v1`, the verifier-expected request/node/role/
tenant/policy/nonce scope and challenge, and the actual response core. The producer
also checks the policy hash/version against its configured registry content and
rejects inconsistent nonce/replay state. Actor
binding is inherited from the authenticated canonical request hash.

The response core excludes only `signature`, `attestation_timestamp`,
`attestation_hash`, `attestation_node_id`, `attestation_provider_mode` and
`hardware_backed`. These are derived after token verification; exclusions avoid
a circular dependency. Response timestamp, reason, decision and all remaining
state fields are committed. The verifier independently recomputes the nonce and
returns a frozen decision whose attestation fields come from verified claims and
server-owned enrollment. Existing node HMACs remain for API compatibility; they
are not Google proof or independent hardware authority.

Approved manifest identity, full argv and explicit environment claims are pinned;
command/environment overrides are rejected. A trusted image must expose only the
reviewed request-to-decision producer, never a general arbitrary-nonce oracle.
Code, launcher arguments, file mounts, process access and key custody inside that
measured workload require operational review. A digest alone does not prove these
deployment facts. Two clients in the same workload are not independent domains.

## Default behavior and trust input

`USBAY_NODE_ATTESTATION_ADAPTER` defaults to unset. Only the exact profile
`google-confidential-space-oidc-rs256-v1` opts in; unsupported values fail closed.
`USBAY_CONFIDENTIAL_SPACE_TRUST_PATH` must reference operator-controlled JSON,
owned by the current user/root and not group/world writable. Missing trust stops.
No example file with live project IDs, keys or enrolled identities is installed.

The unchanged node policy must approve `external_attestation_service` before this
route can be used. The repository's current `mock_local` production policy is
unchanged and remains blocked. A flag alone does not approve that policy change.
`synthetic_fixture=true` is accepted only with `USBAY_ENV=test`; it permits a
task-local fake launcher UDS. Production requires the documented fixed socket.

Verifier-controlled input provides profile, issuer, audience, snapshot issuance/
expiry, bounded acquisition timeout, maximum token lifetime, RSA public-key
snapshots with kid/validity/revocation, a dedicated replay DB path, and per-node
role/tenant enrollment. Each enrollment specifies project ID/number, service
account, exact instance subjects, registry image manifest digest/reference, argv,
explicit environment, approved OS versions and confidential hardware models.
`swversions` is a list of approved single version strings; Google's `swversion`
claim must be an array containing exactly one such version.

The runtime loader fixes Google's issuer. Pure verifier tests may supply a
different explicitly synthetic issuer under test-controlled trust. All test keys,
projects, measurements and identities are synthetic. A Google-shaped issuer URI
signed with test RSA keys is not Google-provider validation.

Strict bounded JSON/JWT parsing rejects duplicate members, nonfinite values,
unsupported algorithms and token-controlled key material/URLs. Only RS256 using
trusted RSA 2048–4096-bit public keys is supported. Key/snapshot validity and
revocation are checked without token-directed discovery. Issuer, exact audience,
iat/nbf/exp, expiry equality, challenge/response, measurements, debug state,
Secure Boot, Confidential Space OS, usable/stable attributes and approved
confidential hardware model are required. A caller's hardware boolean grants
nothing. No generic `PROVIDER-SIGNED` label is treated as a signature mechanism.

## Replay, evidence and deadlines

Authentication and identity validation precede consumption. The adapter reuses
`SQLiteDecisionEvidenceConsumptionStore`'s atomic unique-key insert, through an
open-only subclass that checks an already provisioned schema/integrity and uses
FULL synchronization. Missing/corrupt/locked storage never becomes a new empty
registry. Synthetic fixtures explicitly provision their disposable DB using the
existing store. There is no live provisioning command in this candidate.

Admission key domain-separates tenant/node/role/policy/request/nonce scope and
excludes response timestamp and challenge. A fresh token or challenge for the
same authenticated request cannot bypass consumed history. Invalid evidence does
not consume. A successful consumption is never automatically released after a
lost reply, worker failure or downstream error. Store, diagnostics, audit and node
effects are separate transactions. SQLite protects cooperating processes on one
tested filesystem; coherent store rollback/deletion/replacement, multi-host
currentness and independent preservation remain operational gaps. No process-local
cache is claimed to provide replay protection.

Diagnostics contain bounded stage/code, node, request correlation hash, evidence
digest and worker exit/timeout only. Raw requests, tokens, claims and keys are not
logged. Node-3 transport/mandates, quorum thresholds and consensus audit contracts
remain unchanged. The M1 continuity provider is not relabelled as attestation.

The existing worker default remains one second. Acquisition timeout is explicitly
bounded to at most 0.75 seconds and cannot silently extend the parent deadline.
Synthetic latency is not a live-service latency guarantee. Operational feasibility
of Google's launcher under that budget is unproven; a timeout remains a denial.
Any later operational deadline change requires separate evidence and approval.

## Explicit prerequisites before live deployment

Human owners must approve the exact deployable producer image's registry manifest
digest, code/entrypoint/env restrictions, actual projects, workload identities,
trust roots/key-refresh provenance and revocation ownership. Local Docker image
IDs are configuration-object IDs, not registry manifest digests; none of the old
probe images is asserted deployable as an attested workload.

Separate decisions are required for cloud provisioning, hardened Confidential
Space image/version/platform, node identity enrollment, signed security-policy
migration, durable replay provisioning/preservation, workload separation and
activation. Currentness/recovery and node-3 transport gates remain in force.
Synthetic acceptance, in-process execution and local native workers do not prove
Google service operation, hardware trust, independent quorum or production readiness.

## Official protocol references

- https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources
- https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims

The task evidence retains retrieved documentation and hashes. OIDC discovery/JWKS
locations are documentation references only; this task never calls a live issuer,
metadata service or attestation launcher. Trust snapshot rotation is explicit
operator input and is exercised with synthetic local snapshots.
