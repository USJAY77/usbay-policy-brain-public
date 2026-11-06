# Native component validation and source-bound CI proposal

LOCAL_PREPARATION_ONLY. No branch, pull request, workflow run, merge, deployment,
activation or trust adoption is performed by preparing this batch.

## Component scope

The candidate tests belong under validation/rfc3161/tests. They are new standalone
component tests, not replacements for existing repository tests. pytest.ini's
existing testpaths=tests and its critical/governance/dependency selection remain
unchanged. The dedicated proposed PR job builds the required native helpers and
executes every component case. No existing security test is skipped or weakened.

The 117 earlier component cases plus 18 immutable-source projection cases make
135 unique tests. Source projection tests create disposable synthetic Git repos;
they never commit to the actual USBAY repository or publish anything.

## Immutable source projection

project_source.py requires the exact candidate commit and tree. It reads a fixed
manifest from Git objects, accepts only tracked regular blobs, checks Git blob
identities and bounded sizes, and refuses aliases, path traversal, missing or
duplicate entries, existing destinations and output inside the source checkout.
It copies committed bytes, never working-tree overrides or untracked data.

The manifest includes itself, the existing baseline audit initializer,
requirements-ci.txt and AGENTS.md. Existing baseline bytes are not modified by
the proposed patch. Source receipts bind paths/blob hashes/SHA256/length to the
exact commit/tree; they are evidence, not an attestation or authority.
The verifier rechecks projected sources against immutable Git bytes before and
after memory validation. Source changes fail closed; build outputs and pycache
are not treated as tracked source.

## Proposed CI job

native-timestamp-component.yml runs only for matching same-repository pull requests.
It uses contents:read, persist-credentials:false, no repository secrets, no OIDC
or attestation-write permission, and no production/provider/deployment action.
It reuses checkout@v6, setup-python@v7 and upload-artifact@v4 versions already
listed in the inspected approved-actions policy. Python 3.11 is the existing
hash-locked CI dependency baseline; the local tests used Python 3.12.14.

The job checks out the exact PR head, projects exact Git source, creates a private
venv and installs only the existing hash-locked requirements-ci.txt. It builds
and runs the component tests in that projection, not the application. No sudo,
apt, unshare, sandbox relaxation or root-authority provisioning is added.

validate_native_memory.py requires address, undefined-behavior AND leak checks.
It compiles instrumented wrapper/test helpers and runs actual public/synthetic
cases with bounded CPU, file size, descriptors, timeout and diagnostic capture.
ASan's virtual-address requirement is confined to this sanitizer job; production
verifier resource limits are unchanged. No raw sanitizer output or private keys
are exported. Receipts retain status/reason/source/binary/diagnostic hashes only.

The local environment is known to make LeakSanitizer abort under ptrace. This
script treats that as a hard failure and never retries with leak checks disabled.
Proposed CI success is UNKNOWN until an authorized run establishes it. Linked
OpenSSL itself is not rebuilt with instrumentation; wrapper results are scoped.

## Publication boundary

The complete source patch, file hashes, proposed PR description and validation
plan are prepared for review. Publishing a new draft PR and causing one CI round
on that exact candidate require explicit authorization. A CI round includes
normal mandatory repository checks and the new component job on the same head;
there are no automatic repair commits, retries, merge or activation in this request.

Even green CI would establish component evidence only. Native artifact adoption,
production TSA trust/clock/context, full audit/release/WORM/export integration and
execution authority remain independent gates. Human code review of this proposal
does not adopt the unresolved TSA trust policy.
