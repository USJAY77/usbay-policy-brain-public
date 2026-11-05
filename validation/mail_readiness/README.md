# Governed Mail synthetic isolation preflight

This Draft proposal runs synthetic controls only. It grants no product execution authority and does not run mail/application tests.

## Ephemeral runner mapping repair

The owner authorized a bounded implementation/publication batch and at most two new-head CI rounds using temporary OS mapping permissions. Merge, deployment and activation remain prohibited.

The fixed bootstrap verifies the original nonroot sudo caller, repository owner, exact source HEAD and committed bootstrap/controller/contract bytes. Only the runner UID/GID are mapped to namespace ID0, count1. It preserves existing /etc/subuid and /etc/subgid bytes and metadata, rejects ambiguous/unsafe policy, and holds a root-owned nonblocking lock. It restores its exact changes after the child exits, and fails if either policy update or restoration cannot be verified. No sudoers change, package install or kernel relaxation is included.

Supplementary groups are cleared before unshare. The conflicting --setgid option is removed; the child sets real/effective/saved GID0 with setresgid, verifies empty supplementary groups, exact one-ID maps and permanent setgroups denial before mounting. The fresh constrained child independently verifies its real/effective/saved identity, empty groups and denied setgroups syscall.

The existing user/network/mount/PID namespaces, read-only source/runtime, FD closure, capability removal, no_new_privs and kernel restriction function are retained. The exact ten synthetic controls remain mandatory, as do namespace/fresh-child identity evidence and confirmed mapping-policy restoration. Missing evidence fails closed.

## Limits and stop conditions

The hosted runner is disposable and provides sudo; this is not a hardened multi-tenant bootstrap service. Source identity/byte checks do not make a malicious concurrent owner process trustworthy. Root-level actors are outside the in-job locking threat model. Reuse on a persistent/shared runner is prohibited without separate design and authority.

Pure tests cover exact/broad/root mappings, malformed policy, partial update, restoration, concurrent mutation and identity failures. They do not establish native isolation. No local privileged launch is performed. Native evidence must establish all controls on the exact published head; passing is not exhaustive sandbox proof or Governed Mail production readiness.

The original command grammar, full mail-suite integration, release/provider authority and EGAP-HYDRA-REMOTE-TRANSPORT-AUTH remain open. Stop on a new privilege requirement, unsafe state, unsupported ordering or the two-round budget; never repeat an unchanged failed run.
