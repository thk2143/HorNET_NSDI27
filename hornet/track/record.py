from __future__ import annotations

from typing import Any, Optional

PKT = 0
MAP = 1
CTX = 2
BSS = 3


def _const(x) -> Optional[int]:
    if isinstance(x, int):
        return x
    n = getattr(x, 'num', None)
    return n if isinstance(n, int) and type(x).__name__ == 'num' else None


def may_alias(a, b) -> bool:
    if a.region is None or b.region is None or a.region != b.region:
        return False
    if a.region == MAP:
        if a.map_id != b.map_id:
            return False
        ka, kb = _const(a.map_key), _const(b.map_key)
        if ka is not None and kb is not None and ka != kb:
            return False
    if a.region == BSS:
        ka, kb = getattr(a, 'bss_key', None), getattr(b, 'bss_key', None)
        if ka is not None and kb is not None and ka != kb:
            return False
    if a.var_off is not None or b.var_off is not None:
        return True
    return a.off < b.off + max(b.size, 1) and b.off < a.off + max(a.size, 1)


def build_call_index(blocks: list) -> dict[int, Any]:
    from track.expr import func_retval
    out: dict[int, Any] = {}
    for b in blocks:
        for a in b.actions:
            if getattr(a, 'ret', None) is not None:
                out[a.idx] = a
        for v in b.sources:
            if isinstance(v, func_retval):
                out[v.idx] = v
    return out
