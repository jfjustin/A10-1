"""Quote-aware shell command splitter for the A10 Agent Harness policy engine.

`parse(command)` returns a `ParseResult` with a list of `Segment`s. The goal is
not to be a full shell, but to stop the first-word-only bypass in the starter
policy (`ls; rm demo-files/notes.txt`) by splitting a command into the pieces
that actually run and recording the facts the policy engine needs:

  * each command's argv after quote removal (`'r'm` and `r\\m` both become `rm`)
  * write-redirect targets (`>`, `>>`, `>|`, `&>`, `&>>`, `N>`)
  * a background flag (trailing `&`)
  * the pipeline the command belongs to (to spot `curl ... | sh`)
  * whether the command came from a command/process substitution
  * leading `NAME=value` assignments

Command substitutions `$(...)` / backticks and process substitutions
`<(...)` / `>(...)` are extracted (including inside double quotes) and parsed
recursively as extra segments. Heredoc bodies are consumed as data. Unbalanced
quotes or parentheses set `error` (the policy engine fails such commands closed).

Stdlib only.
"""
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = ["Segment", "ParseResult", "parse"]

_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DEVNULL = {"/dev/null", "/dev/stdout", "/dev/stderr"}

# Control operators that separate simple commands.
_SEPARATORS = {";", "&&", "||", "|", "|&", "\n", "(", ")", "&"}
_PIPE_OPS = {"|", "|&"}


@dataclass
class Segment:
    argv: List[str] = field(default_factory=list)
    assignments: List[str] = field(default_factory=list)
    write_targets: List[str] = field(default_factory=list)
    background: bool = False
    pipeline_id: int = 0
    pipeline_pos: int = 0
    from_substitution: bool = False
    raw: str = ""


@dataclass
class ParseResult:
    segments: List[Segment] = field(default_factory=list)
    error: Optional[str] = None


def _find_matching_paren(s, open_idx):
    """s[open_idx] == '('; return index of the matching ')' or None."""
    depth = 0
    i = open_idx
    n = len(s)
    while i < n:
        c = s[i]
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                return None
            i = j + 1
            continue
        if c == '"':
            i += 1
            while i < n:
                if s[i] == "\\":
                    i += 2
                    continue
                if s[i] == '"':
                    break
                i += 1
            if i >= n:
                return None
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "(":
            depth += 1
            i += 1
            continue
        if c == ")":
            depth -= 1
            if depth == 0:
                return i
            i += 1
            continue
        i += 1
    return None


def _find_backtick(s, i):
    """s[i] == '`'; return index of the closing backtick or None."""
    j = i + 1
    n = len(s)
    while j < n:
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == "`":
            return j
        j += 1
    return None


def _tokenize(s):
    """Return (tokens, error). Tokens are ('WORD', value, subs),
    ('OP', opstr) or ('REDIR', op, is_write, is_heredoc)."""
    tokens = []
    i = 0
    n = len(s)
    error = None
    cur = []            # literal chars of the current word
    cur_subs = []       # substitution inner strings in the current word
    has_word = False
    word_quoted = False
    pending_heredocs = []   # list of (delimiter, strip_tabs)
    state = {"heredoc": None}   # strip flag awaiting the next word as delimiter
    paren_depth = 0

    def flush_word():
        nonlocal cur, cur_subs, has_word, word_quoted
        if has_word:
            val = "".join(cur)
            tokens.append(("WORD", val, cur_subs))
            if state["heredoc"] is not None:
                pending_heredocs.append((val, state["heredoc"]))
                state["heredoc"] = None
            cur = []
            cur_subs = []
            has_word = False
            word_quoted = False

    def pop_fd():
        # Before a < or > redirect: a bare all-digit unquoted word is an fd.
        nonlocal cur, has_word, word_quoted
        if has_word and not word_quoted and "".join(cur).isdigit():
            cur = []
            has_word = False
            word_quoted = False
        else:
            flush_word()

    while i < n:
        c = s[i]

        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                error = "unbalanced single quote"
                break
            cur.append(s[i + 1:j])
            has_word = True
            word_quoted = True
            i = j + 1
            continue

        if c == '"':
            has_word = True
            word_quoted = True
            i += 1
            closed = False
            while i < n:
                d = s[i]
                if d == "\\":
                    if i + 1 < n and s[i + 1] in '$`"\\':
                        cur.append(s[i + 1])
                        i += 2
                        continue
                    if i + 1 < n and s[i + 1] == "\n":
                        i += 2
                        continue
                    cur.append("\\")
                    i += 1
                    continue
                if d == '"':
                    closed = True
                    i += 1
                    break
                if d == "`":
                    k = _find_backtick(s, i)
                    if k is None:
                        error = "unbalanced backtick"
                        break
                    cur_subs.append(s[i + 1:k])
                    i = k + 1
                    continue
                if d == "$" and i + 1 < n and s[i + 1] == "(":
                    k = _find_matching_paren(s, i + 1)
                    if k is None:
                        error = "unbalanced command substitution"
                        break
                    cur_subs.append(s[i + 2:k])
                    i = k + 1
                    continue
                cur.append(d)
                i += 1
            if error:
                break
            if not closed:
                error = "unbalanced double quote"
                break
            continue

        if c == "\\":
            if i + 1 < n:
                if s[i + 1] == "\n":
                    i += 2
                    continue
                cur.append(s[i + 1])
                has_word = True
                i += 2
                continue
            cur.append("\\")
            has_word = True
            i += 1
            continue

        if c == "$" and i + 1 < n and s[i + 1] == "(":
            k = _find_matching_paren(s, i + 1)
            if k is None:
                error = "unbalanced command substitution"
                break
            cur_subs.append(s[i + 2:k])
            has_word = True
            i = k + 1
            continue

        if c == "`":
            k = _find_backtick(s, i)
            if k is None:
                error = "unbalanced backtick"
                break
            cur_subs.append(s[i + 1:k])
            has_word = True
            i = k + 1
            continue

        if c in "<>" and i + 1 < n and s[i + 1] == "(":
            k = _find_matching_paren(s, i + 1)
            if k is None:
                error = "unbalanced process substitution"
                break
            cur_subs.append(s[i + 2:k])
            has_word = True
            i = k + 1
            continue

        if c in " \t":
            flush_word()
            i += 1
            continue

        if c == "#" and not has_word:
            j = s.find("\n", i)
            if j < 0:
                i = n
            else:
                i = j
            continue

        if c == "\n":
            flush_word()
            tokens.append(("OP", "\n"))
            i += 1
            if pending_heredocs:
                for delim, strip in pending_heredocs:
                    while i < n:
                        j = s.find("\n", i)
                        if j < 0:
                            line = s[i:]
                            i = n
                        else:
                            line = s[i:j]
                            i = j + 1
                        check = line.lstrip("\t") if strip else line
                        if check == delim:
                            break
                pending_heredocs = []
            continue

        if c == "&":
            if s[i:i + 3] == "&>>":
                flush_word()
                tokens.append(("REDIR", "&>>", True, False))
                i += 3
                continue
            if s[i:i + 2] == "&>":
                flush_word()
                tokens.append(("REDIR", "&>", True, False))
                i += 2
                continue
            if s[i:i + 2] == "&&":
                flush_word()
                tokens.append(("OP", "&&"))
                i += 2
                continue
            flush_word()
            tokens.append(("OP", "&"))
            i += 1
            continue

        if c == "|":
            if s[i:i + 2] == "||":
                flush_word()
                tokens.append(("OP", "||"))
                i += 2
                continue
            if s[i:i + 2] == "|&":
                flush_word()
                tokens.append(("OP", "|&"))
                i += 2
                continue
            flush_word()
            tokens.append(("OP", "|"))
            i += 1
            continue

        if c == ";":
            flush_word()
            tokens.append(("OP", ";"))
            i += 1
            continue

        if c == "(":
            flush_word()
            tokens.append(("OP", "("))
            paren_depth += 1
            i += 1
            continue

        if c == ")":
            flush_word()
            tokens.append(("OP", ")"))
            paren_depth -= 1
            if paren_depth < 0:
                error = "unbalanced parenthesis"
                break
            i += 1
            continue

        if c == ">":
            pop_fd()
            if s[i:i + 2] == ">>":
                tokens.append(("REDIR", ">>", True, False))
                i += 2
                continue
            if s[i:i + 2] == ">|":
                tokens.append(("REDIR", ">|", True, False))
                i += 2
                continue
            if s[i:i + 2] == ">&":
                tokens.append(("REDIR", ">&", False, False))
                i += 2
                continue
            tokens.append(("REDIR", ">", True, False))
            i += 1
            continue

        if c == "<":
            pop_fd()
            if s[i:i + 3] == "<<<":
                tokens.append(("REDIR", "<<<", False, False))
                i += 3
                continue
            if s[i:i + 3] == "<<-":
                tokens.append(("REDIR", "<<", False, True))
                state["heredoc"] = True
                i += 3
                continue
            if s[i:i + 2] == "<<":
                tokens.append(("REDIR", "<<", False, True))
                state["heredoc"] = False
                i += 2
                continue
            if s[i:i + 2] == "<&":
                tokens.append(("REDIR", "<&", False, False))
                i += 2
                continue
            tokens.append(("REDIR", "<", False, False))
            i += 1
            continue

        cur.append(c)
        has_word = True
        i += 1

    if error:
        return [], error
    flush_word()
    if paren_depth != 0:
        return [], "unbalanced parenthesis"
    return tokens, None


def _make_segment(ctoks, pid, pos, from_sub):
    assignments = []
    argv = []
    write_targets = []
    seen_cmd = False
    i = 0
    while i < len(ctoks):
        t = ctoks[i]
        if t[0] == "REDIR":
            _op, is_write, _hd = t[1], t[2], t[3]
            target = None
            if i + 1 < len(ctoks) and ctoks[i + 1][0] == "WORD":
                target = ctoks[i + 1][1]
                i += 1
            if is_write and target and target not in _DEVNULL:
                write_targets.append(target)
            i += 1
            continue
        if t[0] == "WORD":
            val = t[1]
            if not seen_cmd and _ASSIGN_RE.match(val):
                assignments.append(val)
            else:
                seen_cmd = True
                argv.append(val)
            i += 1
            continue
        i += 1
    raw = " ".join(a for a in argv if a != "")
    for wt in write_targets:
        raw += " > " + wt
    if not raw and assignments:
        raw = " ".join(assignments)
    return Segment(argv=argv, assignments=assignments,
                   write_targets=write_targets, background=False,
                   pipeline_id=pid, pipeline_pos=pos,
                   from_substitution=from_sub, raw=raw)


def _build_segments(tokens, from_sub, pid_start):
    segments = []
    commands = []
    cur = []
    for tok in tokens:
        if tok[0] == "OP" and tok[1] in _SEPARATORS:
            commands.append((cur, tok[1]))
            cur = []
        else:
            cur.append(tok)
    commands.append((cur, None))

    pid = pid_start - 1
    pos = 0
    prev_pipe = False
    last_seg = None
    for ctoks, term in commands:
        has_real = any(t[0] in ("WORD", "REDIR") for t in ctoks)
        if has_real:
            if prev_pipe:
                pos += 1
            else:
                pid += 1
                pos = 0
            seg = _make_segment(ctoks, pid, pos, from_sub)
            segments.append(seg)
            last_seg = seg
        prev_pipe = term in _PIPE_OPS
        if term == "&":
            if last_seg is not None:
                last_seg.background = True
            prev_pipe = False
    next_pid = pid + 1

    # Recurse into command / process substitutions.
    subs = []
    for tok in tokens:
        if tok[0] == "WORD":
            subs.extend(tok[2])
    for sub in subs:
        sub_tokens, suberr = _tokenize(sub)
        if suberr:
            continue
        sub_segs, next_pid = _build_segments(sub_tokens, True, next_pid)
        segments.extend(sub_segs)
    return segments, next_pid


def parse(command):
    if command is None:
        command = ""
    tokens, error = _tokenize(command)
    if error:
        return ParseResult(segments=[], error=error)
    segments, _ = _build_segments(tokens, False, 0)
    return ParseResult(segments=segments, error=None)


def verb_of(segment):
    """basename of argv[0], or '' for an empty/substitution-only segment."""
    if segment.argv and segment.argv[0]:
        return os.path.basename(segment.argv[0])
    return ""
