# PUBLISH — Security Hardening V1 (2026-08-05)

**Audit schema:** `usbay.publish_evidence.v1`
**Timestamp (UTC):** 2026-08-05T05:00:19Z
**Operator:** Replit build agent (Task #25)

---

## 1. Source — Workspace Commit

| Field | Value |
|-------|-------|
| Commit SHA | `d27dd3b` |
| Subject | Improve application routing and security for multiple subdomains |
| Branch | `governance/media-production-gap-scaffolding` |
| Repository | USBAY Replit workspace |

---

## 2. GitHub — Demo Repo Push

| Field | Value |
|-------|-------|
| Repository | `USBAY-GLOBAL/usbay-demo-governance-app` |
| Branch | `main` |
| New commit SHA | `07c2a42bbc76648a754735b96551a57d34af540a` |
| Parent commit | `8168dc2f22fe28e924a1b10c2b38f723fad1e308` |
| Push method | GitHub Git Data API via Replit GitHub connection |

### Files pushed in this delta

- `routing/host_router.py`
- `surfaces/api.py`
- `surfaces/docs.py`
- `surfaces/landing.py`
- `surfaces/pilot.py`
- `surfaces/status.py`
- `tests/test_host_routing.py`

### Changes summary

- `routing/host_router.py`: added `apply_security_headers()` with per-surface
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`,
  and surface-keyed `Cache-Control` (`_CACHE_BY_SURFACE` map).
- `surfaces/pilot.py`: locked shell to "NOT CONFIGURED / RESTRICTED" state with explicit
  `Status: NOT CONFIGURED` pill; no fake auth or placeholder data.
- `surfaces/status.py`, `surfaces/docs.py`, `surfaces/landing.py`, `surfaces/api.py`:
  honest status semantics; surface-level wiring corrections.
- `tests/test_host_routing.py`: added 76-line regression suite covering all surfaces,
  header assertions, and fail-closed paths.

---

## 3. Cloudflare Deploy

| Field | Value |
|-------|-------|
| Worker name | `usbay-demo-governance-app` |
| Worker Version ID | `2362746e-7366-47a9-8bc9-ac46aa10b287` |
| Deploy tool | `npx wrangler deploy` (v4.113.0) |
| Image — previous digest | `sha256:ad18bdea3a918f4fd0a3c802b135a0e841aafe47acebf9ac26c14e110c6fd02d` |
| Image — new digest | `sha256:d4574b8fb266c760d77d4a586b27f23b64ae245f91990e64035f500af528619b` |
| Container registry | `registry.cloudflare.com/5511d4495c7a8466ce6d5962f7493537/usbay-demo-governance-app-usbaygateway` |
| Workers.dev URL | `https://usbay-demo-governance-app.security-usbay1.workers.dev` |

---

## 4. Live Verification

All five checks run fresh at **2026-08-05T05:00:19–05:00:29Z**.

### Check 1 — demo.usbay.global security headers

```
$ curl -sI https://demo.usbay.global/

cache-control: no-cache
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'
permissions-policy: camera=(), microphone=(), geolocation=(), payment=()
referrer-policy: strict-origin-when-cross-origin
x-content-type-options: nosniff
x-usbay-surface: demo
```

**Result: PASS** — `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
`Content-Security-Policy`, and surface-keyed `Cache-Control: no-cache` all present.

---

### Check 2 — pilot.usbay.global restricted marker

```
$ curl -sI https://pilot.usbay.global/

cache-control: no-store
x-content-type-options: nosniff
x-usbay-surface: pilot

$ curl -s https://pilot.usbay.global/ | grep -i "NOT CONFIGURED\|restricted"

<title>USBAY Pilot — Access Restricted</title>
    PILOT ACCESS RESTRICTED &mdash; EXPLICITLY MARKED PREVIEW PAGE ONLY.
      <p style="margin-top:8px"><span class="pill">Status: NOT CONFIGURED</span></p></div>
```

**Result: PASS** — `Status: NOT CONFIGURED` pill present; `Cache-Control: no-store`.

---

### Check 3 — per-surface Cache-Control on go / status / api

```
$ curl -sI https://go.usbay.global/

cache-control: public, max-age=300
x-content-type-options: nosniff
x-usbay-surface: go

$ curl -sI https://status.usbay.global/

cache-control: no-cache
x-content-type-options: nosniff
x-usbay-surface: status

$ curl -sI https://api.usbay.global/

cache-control: no-store
x-content-type-options: nosniff
x-usbay-surface: api
```

**Result: PASS** — go=`public, max-age=300`; status=`no-cache`; api=`no-store` (matches `_CACHE_BY_SURFACE` map).

---

### Check 4 — console.usbay.global still 403

```
$ curl -si https://console.usbay.global/

HTTP/2 403
date: Wed, 05 Aug 2026 05:00:29 GMT
content-type: text/html; charset=utf-8
cache-control: no-store
server: cloudflare
```

**Result: PASS** — 403 fail-closed; `Cache-Control: no-store`.

---

### Check 5 — unknown host 404 (fail-closed)

```
$ curl -si https://<REPLIT_DEV_DOMAIN>/ -H "X-USBAY-Host: evil.notreal.xyz"

HTTP/2 404
content-type: application/json
date: Wed, 05 Aug 2026 05:00:28 GMT
server: uvicorn

{"error":"unknown_host","detail":"Hostname is not a governed USBAY surface (fail-closed)."}
```

**Result: PASS** — host_router rejects unrecognised hostname with 404 + structured error.
Note: `unknown.usbay.global` is not routed to this worker by Cloudflare (unknown subdomains
are dropped at the edge), so this check is exercised via the dev URL with the
`X-USBAY-Host` override that the Cloudflare worker sets in production.

---

## 5. Overall Result

| Check | Surface | Result |
|-------|---------|--------|
| Security headers (X-Content-Type-Options etc.) | demo, pilot, go, status, api | **PASS** |
| Pilot NOT CONFIGURED restricted marker | pilot | **PASS** |
| Per-surface Cache-Control | go/status/api/demo/pilot/console | **PASS** |
| Console locked (403) | console | **PASS** |
| Unknown host fail-closed (404) | host_router | **PASS** |

**5 / 5 checks passed.** Production matches workspace commit `d27dd3b`.
