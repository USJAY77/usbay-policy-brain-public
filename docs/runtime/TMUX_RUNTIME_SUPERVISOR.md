# USBAY TMUX Runtime Supervisor

Local process supervisor for USBAY development/runtime sessions using tmux.
Design-first, local-only scaffolding — no production activation, no provider
calls, no governance changes.

## Purpose

Run the gateway, tests, audit-log tail, and health monitoring in isolated
tmux panes inside a single named session (`usbay-runtime`) so a developer can:

- observe the gateway and its health side by side,
- restart individual concerns without killing the others,
- keep read-only audit evidence continuously visible.

## Session layout

Session name: `usbay-runtime` (single window, four panes)

| Pane | Name | What it runs |
|---|---|---|
| 0 | gateway | `python3 -m uvicorn gateway.app:app --host 127.0.0.1 --port ${PORT:-5000}` (localhost-only dev server) |
| 1 | tests | idle shell pre-printed with the standard local pytest suites |
| 2 | audit-log | read-only `tail -F` of `evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md` |
| 3 | health-watch | read-only GET polling of `/health`, `/api/runtime/health`, `/execute` every 10s |

## Commands

```bash
bash scripts/usbay_tmux_start.sh    # create the usbay-runtime session (fails if tmux missing or session exists)
bash scripts/usbay_tmux_status.sh   # report session existence + list panes (exit 1 if not running)
bash scripts/usbay_tmux_stop.sh     # stop ONLY the usbay-runtime session
tmux attach -t usbay-runtime        # attach interactively
```

## Safety boundaries

- **Local only.** Only localhost dev commands are launched. No production
  commands, no deploy, no activation of any external environment.
- **No provider/API/LLM calls.** The health-watch pane issues read-only GETs
  against the local gateway; nothing leaves the machine.
- **No secrets.** Scripts never read, echo, or list environment variables or
  credential material. Status output is tmux structural metadata only.
- **Governance untouched.** The supervisor runs existing commands; it does not
  modify Policy Brain, Enforcement Gateway, runtime validator, `/execute`
  semantics, or audit-chain logic.
- **Scoped teardown.** `usbay_tmux_stop.sh` kills only the `usbay-runtime`
  session — never other sessions, never the tmux server.

## Fail-closed notes

- Every script exits non-zero immediately if `tmux` is not installed
  (no fallback supervision is attempted).
- `usbay_tmux_start.sh` refuses to run if the session already exists
  (no silent re-use or pane duplication).
- The audit-log pane is read-only; if the evidence file does not exist yet it
  reports that fact and creates nothing.
- The health-watch pane only reports status codes; the expected demo-safe
  contract remains `GET /execute -> 404`.

## Audit evidence expectations

- The audit-log pane keeps the stability-gate report
  (`evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md`) visible; that file is
  rewritten only by the `game-stability` gate, never by these scripts.
- The health-watch pane provides a continuous, timestamped, read-only trace of
  `/health`, `/api/runtime/health`, and `/execute` status codes suitable for
  screenshots or session logs during demos.
- These scripts themselves write no evidence files and mutate no state beyond
  the tmux session they own.

## Known limitation

`tmux` is not currently installed in this Replit environment; the scripts
fail closed by design until it is added (e.g., as a system dependency). The
scaffolding is validated via `bash -n` and is ready to use on any machine with
tmux available.
