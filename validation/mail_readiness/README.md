# Exact-parent pre-map group-denial correction — NATIVE VALIDATION PENDING

Native round2 at head4c1ea59f106fd3c111579c32389f994dbe6f9082 failed while unshare wrote deny after gid_map. Kernel proc_setgroups_write rejects deny once gid_map has extents. The previous bootstrap sequence was incorrect.

This candidate changes the sequence, not the required protection: a root-owned ephemeral helper denies setgroups BEFORE publishing the single-GID map. The helper accepts only its actual parent PID, one exact owner GID and a pinned proc-directory FD; verifies the separate user namespace and exact previously written UID map; rejects existing GID mappings, unknown states and invalid arguments. Source bytes and an exact-head/UID/GID binding are copied into a root-owned mode700 directory under /run. No shell or arbitrary target path is accepted. The real UID helper remains unchanged.

The fixed helper writes /proc/<verified-parent>/setgroups and gid_map. This is an explicit change to the privileged bootstrap protocol and must be reviewed before publication/native execution; a generic product authority grant does not authorize it. Only one original nonroot owner mapping is permitted. The original ten controls, pre-mount and fresh-child identity checks, permanent group denial, policy restoration and unchanged kernel restrictions remain mandatory.

79 local pure tests passed, including nine model tests and five target-binding tests of the kernel ordering and failure cases. No local privileged setup, /proc or /etc writes, namespace launch or application tests occurred. Full helper PID/namespace/proc-FD integration remains UNKNOWN. This is not a security-reviewed or native-validated bootstrap.

The previous two-round repair budget was consumed. The owner separately authorized publication of this exact bounded protocol and one additional synthetic CI round. No unchanged retry or further round is authorized. No merge, deployment, activation or mail/application tests.

Primary sources:
https://github.com/torvalds/linux/blob/v6.8/kernel/user_namespace.c (proc_setgroups_write)
https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c
https://github.com/shadow-maint/shadow/blob/4.13/src/newgidmap.c
