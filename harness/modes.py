"""The mode table (✅ allow · ❓ ask · ⛔ block)."""
from __future__ import annotations

ALLOW, ASK, BLOCK = "allow", "ask", "block"
SEVERITY = {ALLOW: 0, ASK: 1, BLOCK: 2}

#       row: (action,                                      plan,  default, auto)
TABLE: dict[int, tuple[str, str, str, str]] = {
    1:  ("Read inside the workspace",                     ALLOW, ALLOW, ALLOW),
    2:  ("Read outside the workspace",                    ASK,   ASK,   ALLOW),
    3:  ("Write or edit inside the workspace",            BLOCK, ASK,   ALLOW),
    4:  ("Write outside the workspace",                   BLOCK, BLOCK, ASK),
    5:  ("A single read-only shell command",              ALLOW, ALLOW, ALLOW),
    6:  ("Other shell commands",                          BLOCK, ASK,   ALLOW),
    7:  ("Package installs",                              BLOCK, ASK,   ASK),
    8:  ("Web request to an allowlisted host",            ALLOW, ALLOW, ALLOW),
    9:  ("Web read from an unknown public host",          ASK,   ASK,   ALLOW),
    10: ("Calls to the LLM provider",                     ALLOW, ALLOW, ALLOW),
    11: ("Subagents and background tasks",                BLOCK, ASK,   ALLOW),
    12: ("Scheduled or remote actions that outlive the run", BLOCK, BLOCK, ASK),
    13: ("MCP tools",                                     ASK,   ASK,   ASK),
    14: ("Unknown tools",                                 BLOCK, ASK,   ASK),
    15: ("Housekeeping tools",                            ALLOW, ALLOW, ALLOW),
}
_COL = {"plan": 1, "default": 2, "auto": 3}


def verdict(row: int, mode: str) -> str:
    return TABLE[row][_COL[mode]]


def strictest(rows: list[int], mode: str) -> tuple[str, int]:
    """Verdict for an action that falls into several rows: the strictest one wins."""
    best = (ALLOW, rows[0] if rows else 15)
    for r in rows:
        v = verdict(r, mode)
        if SEVERITY[v] > SEVERITY[best[0]]:
            best = (v, r)
    return best
