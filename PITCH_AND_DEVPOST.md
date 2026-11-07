# A10 Prompt 2 — 60-second pitch + DevPost skeleton

Prepared 2026-11-07 ~09:05 PT, updated ~14:00 PT for the v2 build
(one harness command, network proxy, pause-for-approval). Verified run
that afternoon: 11-record hash-chained audit — 7 ALLOW, 2 BLOCK, 1
paused-and-approved upload, notes.txt survived.
Edit the bracketed bits to match what the team actually builds today.

## 60-second pitch (read it aloud, ~55 sec at normal pace)

> "AI agents act on their own now — they run shell commands, move files,
> call APIs. But nobody watches what they actually do.
>
> So we built a control layer: every tool call from the agent routes
> through our gateway first, and every network call goes through our
> proxy. A policy engine judges it before it runs — destructive shell
> commands are always blocked, file access stays inside the workspace,
> outbound calls go only to allowlisted hosts, and anything unknown is
> denied by default. Risky actions don't get blocked or waved through —
> they pause for a human to approve. Every verdict, allow or block or
> approve, goes into a hash-chained audit log, and an operator can stop
> the run at any time.
>
> Watch: one command launches the agent. It lists files, reads a note,
> writes a summary, checks an allowlisted API through the proxy — all
> allowed, streaming live. Then it tries to upload the summary — paused,
> we approve it on the dashboard, and it goes through. Then it tries to
> delete the notes file — blocked, with the reason on screen. Then it
> tries to exfiltrate that file to an outside host — blocked again. The
> file is still there. We hit stop, and the audit chain verifies.
>
> Measured result: 2 out of 2 disallowed actions blocked, 1 risky
> upload paused and approved by a human, 0 destructive effects, audit
> chain verified. Agents can act — with a human in control."

Demo beats (same order as the script): benign traffic streams through the
proxy → upload paused, operator approves → `rm` blocked with reason →
exfil curl blocked with reason → STOP RUN → `/audit` verifies the chain.

## If judges ask

- "What if the agent is smarter / uses an LLM?" — The gateway doesn't
  care who calls it. Swap the scripted steps in `agent.py` for an LLM
  loop and the policy layer works the same. (README build-list item 1;
  scripted agent is the fallback and already demos end-to-end.)
- "Can policies grow?" — Yes: block writes matching secret patterns,
  rate-limit repeated calls, per-agent allowlists. (README item 2.)
- "How is this different from just logging?" — Logging watches after the
  fact. The gateway judges *before* execution, so the destructive action
  never runs — proven by `notes.txt` surviving.
- Relation to prior work: same shape as the Oct 12 triage-bench —
  ingest → policy/score → allow/block → audit log — and the live
  dashboard reuses the `report.html` pattern.

## DevPost submission — requirements verified on a10-x-aws-hack-26.devpost.com, Sat Nov 7 ~11:05 PT

Required (no submission without these):
- **Git repo link** — push the code to GitHub before 9:00 AM Sun; a local-only folder does not count. Make the repo public (or at least link-accessible) and put the README's two-terminal run instructions at the top.
- **Every teammate added** to the DevPost project — collect everyone's DevPost account before submitting; one missing teammate = incomplete submission.

Recommended extras (worth doing if time allows — they feed the "Polish" and "Project Completeness" criteria):
- **Short video demo** (screen-record the 60-sec demo: traffic streaming → rm blocked → exfil blocked → STOP → audit verifies). Record it once the build is frozen, not before — a stale video showing an older build hurts more than no video.
- **Demo slides** (the pitch above, 3–4 slides max) + **screenshots** of the dashboard mid-demo + a **logo/thumbnail**.

Judging criteria (from the DevPost page) and what to lean on:
- **Technology** — policy-before-execution + hash-chained audit, stdlib-only/offline.
- **Polish** — live dashboard, every block carries a reason.
- **Innovativeness** — the gateway judges *before* the action runs, not just logs after.
- **Use of AWS Tech** — note: this is a listed criterion for the event as a whole. The A10-track build is stdlib-only by design (works offline at the venue); if the team has spare time, one small honest AWS touch (e.g. hosting the dashboard/recording) is a bonus, not a requirement — do not re-architect for it overnight.
- **Project Completeness** — the demo must run end-to-end without obstacles; re-run gateway + agent once from a clean checkout before recording/submitting.

## DevPost skeleton (submit by Sun 9:00 AM; demos/judging from 9:15, finalists 11:00, winners ~11:45)

- **Title options:** "Agent Harness — a control layer for CLI agents" /
  "Watchtower: every agent action, judged before it runs"
- **What it does:** One command launches a CLI agent behind a gateway
  and a network proxy; policy engine allows/blocks/pauses-for-approval
  before execution; live dashboard streams traffic with a STOP RUN
  button; hash-chained audit log proves what happened. Demo: benign
  steps allowed through the proxy, 1 risky upload paused and approved,
  `rm` + exfil curl blocked, file survives, audit verifies.
- **How we built it:** Python stdlib only (no pip install, works offline
  at the venue) — `harness.py` (one command), `gateway.py`, `proxy.py`,
  `policy.py`, `agent.py`, live dashboard on http://127.0.0.1:8000/.
  5 policy rules, each block carries a reason.
- **Challenges:** Making the block happen *before* execution, not after;
  keeping the demo visual in 60 seconds; tamper-evident audit chain.
- **What's next:** LLM-driven agent brain behind the same gateway;
  secret-pattern blocks, rate limits, per-agent allowlists; export audit
  JSONL for judges.
- **Built with:** Python (stdlib only). **Track:** A10, Prompt 2 — Agent Harness.

## Today (Sat Nov 7) / tomorrow (Sun Nov 8)

- Check-in 9:00 AM, Heafey Atrium / Bergin; hacking from 11:00 AM, overnight.
- Copy this whole folder to the laptop; run `python3 harness.py` once
  to confirm (approve the paused upload on the dashboard when it
  appears), then POST /reset or delete `audit.log.jsonl` for a clean demo.
- Weather: Sat high 76°F, sunny, rain 0% in the day; overnight low 54°F,
  rain ~20% late night (11 PM–8 AM); Sun high 73°F, AM clouds / PM sun.
  Bring a warm layer for the overnight.
- Sun 9:00 AM DevPost due — leave buffer to upload before demos at 9:15.
