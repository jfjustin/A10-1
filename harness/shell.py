"""Split a shell command into the simple commands it would run.

G2 has to look at *every* part of a command, so `ls; rm demo-files/notes.txt`
is two commands, not one `ls`. We split on ; && || | & and newlines, pull out
the bodies of $(...), <(...), >(...) and backticks, and look inside
`bash -c '...'` / `sh -c` / `eval`. Quotes are respected, so `echo "a; b"` is
one command.

This is a best-effort parser, not a full shell. Anything it can't reason about
(e.g. `python -c`) falls into "other shell commands", which pauses in default mode.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# Commands that just run another command; we look through them.
WRAPPERS = {"env", "nohup", "time", "nice", "timeout", "command", "exec", "builtin",
            "xargs", "stdbuf", "ionice", "caffeinate", "unbuffer"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", ">&"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class Segment:
    text: str
    sep: str = ""                       # separator before this command: ; && || | & \n $( ` -c
    argv: list[str] = field(default_factory=list)
    write_targets: list[str] = field(default_factory=list)   # > file, >> file
    read_targets: list[str] = field(default_factory=list)    # < file

    @property
    def cmd(self) -> str:
        return self.argv[0] if self.argv else ""

    @property
    def args(self) -> list[str]:
        return self.argv[1:]


def _match_paren(s: str, i: int) -> int:
    """s[i] is just after '(' — return index of the matching ')' (or len(s))."""
    depth, quote = 1, None
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)


def _split_top(cmd: str) -> list[tuple[str, str]]:
    """Return [(separator, text)] for top-level commands plus substitution bodies."""
    out: list[tuple[str, str]] = []
    nested: list[tuple[str, str]] = []
    buf: list[str] = []
    sep = ""
    quote = None
    i = 0

    def flush(new_sep: str):
        nonlocal buf, sep
        text = "".join(buf).strip()
        if text:
            out.append((sep, text))
        buf, sep = [], new_sep

    while i < len(cmd):
        c = cmd[i]
        nxt = cmd[i + 1] if i + 1 < len(cmd) else ""
        if quote == "'":
            buf.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\":
            buf.append(cmd[i:i + 2])
            i += 2
            continue
        # Command substitution runs even inside double quotes.
        if (c == "$" and nxt == "(") or (c in "<>" and nxt == "(" and quote is None):
            end = _match_paren(cmd, i + 2)
            nested.extend(("$(", t) for _, t in _split_all(cmd[i + 2:end]))
            buf.append(" __SUBST__ ")
            i = end + 1
            continue
        if c == "`":
            end = cmd.find("`", i + 1)
            end = len(cmd) if end == -1 else end
            nested.extend(("`", t) for _, t in _split_all(cmd[i + 1:end]))
            buf.append(" __SUBST__ ")
            i = end + 1
            continue
        if quote == '"':
            buf.append(c)
            if c == '"':
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
            buf.append(c)
            i += 1
            continue
        if c in ";\n":
            flush(c if c == ";" else "\n")
            i += 1
            continue
        if c == "&" and nxt == "&":
            flush("&&"); i += 2; continue
        if c == "|" and nxt == "|":
            flush("||"); i += 2; continue
        if c == "|":
            flush("|"); i += 2 if nxt == "&" else 1; continue
        if c == "&":
            prev = cmd[i - 1] if i else ""
            if prev in "<>" or nxt == ">":          # 2>&1, &>file
                buf.append(c); i += 1; continue
            flush("&"); i += 1; continue
        if c in "()":
            # Subshells: treat the parentheses as whitespace.
            buf.append(" "); i += 1; continue
        buf.append(c)
        i += 1
    flush("")
    return out + nested


def _tokenize(text: str) -> list[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars="<>&")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes: fall back to a plain split
        return text.split()


KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until"}


def _strip_wrappers(argv: list[str]) -> list[str]:
    while argv:
        if _ASSIGN.match(argv[0]) or argv[0] in KEYWORDS:
            argv = argv[1:]
            continue
        head = os.path.basename(argv[0].lstrip("\\"))
        if head not in WRAPPERS:
            break
        argv = argv[1:]
        # Skip the wrapper's own options and arguments (timeout 5, nice -n 10, env -i ...)
        while argv and (argv[0].startswith("-") or _ASSIGN.match(argv[0])
                        or (head in {"timeout", "nice"} and re.fullmatch(r"[\d.]+[smhd]?", argv[0]))):
            argv = argv[1:]
    if argv:
        argv = [os.path.basename(argv[0].lstrip("\\"))] + argv[1:]
    return argv


def _parse(sep: str, text: str) -> list[Segment]:
    tokens = _tokenize(text)
    words, writes, reads = [], [], []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in WRITE_REDIRECTS or t == "<" or t == "<<" or t == "<<<":
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if t in WRITE_REDIRECTS and not target.isdigit() and target != "-":
                writes.append(target)
            elif t == "<":
                reads.append(target)
            i += 2
            continue
        if t in {"&", "<>"}:
            i += 1
            continue
        words.append(t)
        i += 1
    seg =Segment(text=text, sep=sep, argv=_strip_wrappers(words), write_targets=writes, read_targets=reads)
    result = [seg]
    if seg.cmd in SHELLS and "-c" in seg.args:
        idx = seg.args.index("-c")
        if idx + 1 < len(seg.args):
            result += [Segment(s.text, "-c", s.argv, s.write_targets, s.read_targets)
                       for s in split_command(seg.args[idx + 1])]
    elif seg.cmd == "eval" and seg.args:
        result += split_command(" ".join(seg.args))
    return result


def _split_all(cmd: str) -> list[tuple[str, str]]:
    return _split_top(cmd)


def split_command(cmd: str) -> list[Segment]:
    segments: list[Segment] = []
    for sep, text in _split_top(cmd):
        segments.extend(_parse(sep, text))
    return segments
