# A10 Track — Prompt 2: Agent Harness

**Prompt (from aws.scuacm.com, screenshot 2026-11-06):** Build a control layer
for desktop and CLI-based AI agents that routes requests through a gateway.
**Demo required:** Launch a CLI agent, display its traffic, block a disallowed
action, and stop the run.

**Scope for this build: CLI agents only.** Desktop apps are out of scope —
one harness command launches the agent behind the gateway and a network
proxy, streams its traffic, blocks disallowed actions, pauses risky ones
for operator approval, and kills the run on STOP.

## Why Prompt 2 (not Prompt 1)

Prompt 1 (Agentic Identity) needs real identity plumbing — token issuance,
workload identity, enterprise auth — which this team hasn't built. Prompt 2 is
the same shape as work already shipped: ingest → policy check → allow/block →
audit log is exactly triage-bench, and the live-traffic dashboard is the same
muscle as `report.html`.

## What this does (verified working, 2026-11-07 ~13:45 PT)

- `harness.py` — **one command launches everything:** gateway, network
  proxy, then the CLI agent behind both. Streams the agent's output live,
  watches for STOP, kills the agent and shuts everything down.
- `gateway.py` — stdlib-only gateway + live dashboard on
  http://127.0.0.1:8000/ (no pip install, works offline at the venue).
  Every tool call is judged by `policy.py` **before** it runs, and appended
  to a hash-chained `audit.log.jsonl` (same pattern as triage-bench's
  `triage/audit.py` — tamper with a line and `/audit` fails).
- `proxy.py` — network proxy on http://127.0.0.1:8080/. All agent egress
  runs through it; for every request it asks the gateway, which judges the
  host against the same allowlist. Plain HTTP is forwarded (or 403);
  CONNECT tunnels are opened only for allowlisted hosts. The exfil curl
  is blocked twice over: the gateway blocks the shell command before it
  runs, and the proxy would block the egress even if the agent went rogue.
- `policy.py` — 5 small, judge-explainable rules:
  1. destructive shell verbs (`rm`, `rmdir`, `dd`, …) always blocked;
  2. writes/reads only inside `demo-files/` (the workspace);
  3. outbound calls only to allowlisted hosts (`api.example.com`,
     `127.0.0.1` for local services);
  4. **risky actions pause for approval** — data uploads (`curl -d`,
     POST) return PENDING; the agent waits, the operator approves or
     denies on the dashboard, the decision is written to the audit log;
  5. unknown tools denied by default. Every block carries a reason.
- `agent.py` — demo CLI agent, task "organize these files and look up the
  project status": 4 benign steps (the API lookup and the upload are real
  curls through the proxy), 1 risky upload that pauses for approval, 2
  planted disallowed steps (`rm demo-files/notes.txt`, exfil curl to
  `exfil.evil.example`), then a re-read proving `notes.txt` survived.
- Dashboard — live traffic table, allow/block/pending counters, a pending
  approval box with Approve/Deny buttons, audit-chain badge, big red
  **STOP RUN** button (further calls get 503 `stopped`; the harness kills
  the agent), Reset for a clean re-demo.

Measured run (clean, 2026-11-07): 11 audit events — 7 allow, 2 block,
1 paused-and-approved upload, audit chain ✓ verified; `notes.txt`
survived; the approved upload returned `{"ok": true, "received_bytes": 29}`.

## Run it (one command)

```bash
cd workspace/hackathon/a10-harness
python3 harness.py              # gateway + proxy + agent; dashboard at :8000
```

Approve the paused upload on the dashboard when it appears, then hit
**STOP RUN** and show `/audit` verifying the chain. Manual mode (if you
want it): `python3 gateway.py` in one terminal, `python3 proxy.py` in a
second, `python3 agent.py` in a third — the agent needs the proxy env
(`HTTP_PROXY=http://127.0.0.1:8080`, both cases, `NO_PROXY` cleared for
its shell steps; `harness.py` sets all of this for you).

## 60-second demo beats

1. "Agents act; nobody watches what they do." One command launches the agent.
2. Dashboard streams benign traffic live (list → read → write → allowlisted
   API lookup through the proxy).
3. Agent tries to upload the summary → **PAUSED for operator approval**;
   approve it on the dashboard and the upload goes through.
4. Agent tries `rm` → **BLOCKED, reason on screen**. Tries exfil curl →
   **BLOCKED, reason on screen**. `notes.txt` is still there.
5. Operator hits STOP RUN → agent exits. Audit trail shown, chain verifies.

## Tomorrow's build list (in priority order)

1. **Real agent brain (optional, only if time):** swap the scripted steps in
   `agent.py` for an LLM loop that picks tools — keep the gateway in front;
   the policy layer doesn't care who calls it. Fallback is the scripted
   agent, which already demos end-to-end.
2. **More policy rules:** block `file_write` of secrets patterns, rate-limit
   repeated calls, per-agent allowlists (two agents, different permissions).
3. **Dashboard polish:** filter by verdict, export audit JSONL for judges.
4. **Pitch:** reuse the triage-bench 60-sec structure — problem → ranked/
   explained output → human control → measured result. Here the measured
   result is "2/2 disallowed actions blocked, 1 risky upload paused and
   approved, 0 destructive effects, audit chain verified".
5. **DevPost:** submit by Sun 9 AM; demos/judging from 9:15, finalists 11 AM,
   winners ~11:45. Sign-ups closed Fri 11/6; team is set (grad-only A10
   track, no Sarah).

## Files

- `harness.py`, `gateway.py`, `proxy.py`, `policy.py`, `agent.py` — the
  harness (stdlib only)
- `demo-files/notes.txt` — the file the planted `rm` tries to delete
- `audit.log.jsonl` — created on first run; delete it (or POST /reset) for a clean demo
