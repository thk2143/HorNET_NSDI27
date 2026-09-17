from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from z3 import BitVecVal, Bool, Select, is_true

from track.encode import _map_key_z3


@dataclass
class Witness:
    packet:       bytes = b''
    pkt_len:      int = 0
    maps:         dict = field(default_factory=dict)
    helpers:      dict = field(default_factory=dict)
    ctx:          dict = field(default_factory=dict)
    path:         list = field(default_factory=list)
    failed_atoms: list = field(default_factory=list)

    _model:  Any = field(default=None, repr=False)
    _fwd:    Any = field(default=None, repr=False)
    _target: Any = field(default=None, repr=False)
    _stages: Any = field(default=None, repr=False)

    @property
    def stages(self) -> list:
        if self._stages is None:
            try:
                self._stages = _stages(self._model, self._fwd, self.path,
                                       self._target)
            except Exception:
                self._stages = []
        return self._stages

    def render(self, pipeline: bool = True) -> str:
        out = []
        if self.packet:
            shown = ('' if len(self.packet) >= self.pkt_len
                     else f', first {len(self.packet)} shown')
            out.append(f'packet ({self.pkt_len} bytes{shown}): '
                       f'{_hexdump(self.packet)}')
            desc = _describe(self.packet)
            if desc:
                out.append(f'  as: {desc}')
        if self.ctx:
            out.append('ctx: ' + ', '.join(f'{k}={v}' for k, v in sorted(self.ctx.items())))
        for name, entries in sorted(self.maps.items()):
            for key, (present, value) in sorted(entries.items()):
                state = 'hit' if present else 'miss'
                shown = f' value=0x{value:x}' if present and value is not None else ''
                out.append(f'map {name}[0x{key:x}]: {state}{shown}')
        for (imm, idx), val in sorted(self.helpers.items()):
            out.append(f'helper imm={imm} @idx={idx} -> {val}')
        if self.path:
            out.append('path: ' + ' -> '.join(str(b) for b in self.path))
        if pipeline and self._fwd is not None and self.stages:
            out += _render_stages(self.stages)
        if self.failed_atoms:
            out.append('false atoms: ' + '; '.join(self.failed_atoms))
        return '\n'.join(out)


def _hexdump(data: bytes, per_line: int = 16) -> str:
    if len(data) <= per_line:
        return data.hex(' ')
    lines = [data[i:i + per_line].hex(' ') for i in range(0, len(data), per_line)]
    return '\n        '.join(lines)


def _as_long(model, term, default=None):
    if term is None:
        return default
    try:
        v = model.eval(term, model_completion=True)
        return v.as_long()
    except Exception:
        return default


def _eval_bool(model, term) -> bool:
    if term is True or term is False:
        return bool(term)
    try:
        return is_true(model.eval(term, model_completion=True))
    except Exception:
        return False


DISPLAY_BYTES = 128


def _packet(model, init_st):
    dom = init_st.pkt.domain().size()
    total = _as_long(model, init_st.pkt_len, 0) or 0
    total = max(0, min(total, 1 << dom))
    n = min(total, DISPLAY_BYTES)
    data = bytes((_as_long(model, Select(init_st.pkt, BitVecVal(i, dom)), 0) or 0) & 0xFF
                 for i in range(n))
    return data, total


def _describe(data: bytes) -> str:
    if not data:
        return ''
    try:
        from scapy.layers.l2 import Ether
        return Ether(data).summary()
    except Exception:
        return ''


def _map_name(maps, map_id):
    for m in maps:
        if m.get('id') == map_id:
            return m.get('name') or f'map{map_id}'
    return f'map{map_id}'


def _maps(model, ctx):
    out = {}
    for rec in ctx.calls.values():
        if getattr(rec, 'ret', None) != 'map_ptr':
            continue
        map_id, key_expr = rec.map_id, rec.map_key
        if map_id is None or map_id < 0 or key_expr is None:
            continue
        try:
            key_z3 = _map_key_z3(ctx.st, map_id, key_expr)
        except Exception:
            continue
        key = _as_long(model, key_z3)
        if key is None:
            continue
        present = _eval_bool(model, Select(ctx.init_st.map[map_id][0], key_z3))
        value = _as_long(model, Select(ctx.init_st.map[map_id][1], key_z3))
        out.setdefault(_map_name(ctx.maps, map_id), {})[key] = (present, value)
    return out


def _helpers(model, ctx):
    from track.expr import func_retval
    from track.encode import expr_to_z3
    out = {}
    for rec in ctx.calls.values():
        if isinstance(rec, func_retval):
            out[(rec.func, rec.idx)] = _as_long(model, expr_to_z3(rec, ctx.st))
    return out


def _path(model, ctx, stop_at=None):
    path, b, seen = [0], 0, {0}
    while True:
        info = ctx.info.get(b)
        s = ctx.blocks[b] if 0 <= b < len(ctx.blocks) else None
        if info is None or s is None or s.kind == 'exit':
            break
        if stop_at is not None and b == stop_at:
            break
        nxt = None
        if s.succ_t is not None and _eval_bool(model, info.edge_taken):
            nxt = s.succ_t
        elif s.succ_f is not None and _eval_bool(model, info.edge_fall):
            nxt = s.succ_f
        if nxt is None or nxt in seen or nxt not in ctx.info:
            break
        path.append(nxt)
        seen.add(nxt)
        b = nxt
    return path


def _failed_atoms(model, node, st, out=None):
    if out is None:
        out = []
    if node is None:
        return out
    if node.op == 'leaf':
        try:
            if not _eval_bool(model, node.atom.to_z3(st)):
                out.append(_atom_str(node.atom))
        except Exception:
            pass
        return out
    for c in node.children:
        _failed_atoms(model, c, st, out)
    return out


def _atom_str(atom) -> str:
    cls = type(atom).__name__
    fields = {k: v for k, v in vars(atom).items() if not k.startswith('_')}
    hide  = ('parts', 'retval')
    parts = ', '.join(f'{k}={v!r}' for k, v in fields.items() if k not in hide)
    return f'{cls}({parts})'


_MAP_REF = re.compile(r'\bmap(\d+)\b')

XDP_ACTIONS = {0: 'XDP_ABORTED', 1: 'XDP_DROP', 2: 'XDP_PASS',
               3: 'XDP_TX', 4: 'XDP_REDIRECT'}

COND_CHARS = 92
OPS_PER_STAGE = 12


@dataclass
class Stage:
    block:  int
    kind:   str
    frm:    Optional[int] = None
    edge:   Optional[str] = None
    match:  str = ''
    ops:    list = field(default_factory=list)
    ret:    str = ''
    target: bool = False


def _render_stages(stages: list) -> list:
    body, shown = [], 0
    for s in stages:
        rows = []
        if s.match:
            rows.append(('match', f'{s.match}   [b{s.frm} {s.edge}]'))
        rows += s.ops[:OPS_PER_STAGE]
        if len(s.ops) > OPS_PER_STAGE:
            rows.append(('', f'... +{len(s.ops) - OPS_PER_STAGE} more'))
        if s.ret:
            rows.append(('return', s.ret))
        if not rows:
            continue
        shown += 1
        head = f'b{s.block}' + ('*' if s.target else '')
        for i, (tag, text) in enumerate(rows):
            body.append(f'  {head if i == 0 else "":<7}{tag:<7}{text}')
    count = (f'{len(stages)} stage(s)' if shown == len(stages)
             else f'{shown} of {len(stages)} stage(s)')
    out = [f'pipeline: {count}, b{stages[0].block} -> b{stages[-1].block}'] + body
    if any(s.target for s in stages):
        out.append('  (* = the block this condition was checked at)')
    return out


def _named(text: str, ctx) -> str:
    return _MAP_REF.sub(lambda m: _map_name(ctx.maps, int(m.group(1))), text)


def _clip(text: str, n: int = COND_CHARS) -> str:
    return text if len(text) <= n else text[:n - 1] + '…'


def _negate(text: str) -> str:
    if text.startswith('!'):
        return text[1:]
    if text == 'adjust-success':
        return 'adjust-failed'
    if text == 'adjust-failed':
        return 'adjust-success'
    if text.startswith('(') and text.endswith(')'):
        return '!' + text
    return f'!({text})'


def _hex(v) -> str:
    return '?' if v is None else (f'0x{v:x}' if v >= 0 else str(v))


def _value(model, ctx, expr):
    if expr is None:
        return None
    from track.encode import expr_to_z3
    try:
        return _as_long(model, expr_to_z3(expr, ctx.st))
    except Exception:
        return None


def _addr(off, var_off, size) -> str:
    at = f'<var> + {off:#x}' if var_off is not None else f'{off:#x}'
    return at if size == 1 else f'{at}:+{size}'


def _slot(model, ctx, map_id, map_key) -> str:
    name = _map_name(ctx.maps, map_id)
    try:
        key = _as_long(model, _map_key_z3(ctx.st, map_id, map_key))
    except Exception:
        key = None
    return f'{name}[{_hex(key)}]'


def _helper_name(imm: int) -> str:
    from verify.spec import HELPER_IMM
    for name, i in HELPER_IMM.items():
        if i == imm:
            return name
    return f'helper#{imm}'


def _lookup_hit(model, ctx, act, block) -> Optional[bool]:
    from track.encode import contain_map_value
    if act.map_id is None or act.map_id < 0 or act.map_key is None:
        return None
    try:
        cond = contain_map_value(act.map_id, act.map_key, act.map_key_id, True)
        return _eval_bool(model, cond.to_z3(ctx.state_at(block)))
    except Exception:
        return None


def _op_row(model, ctx, obj, block):
    from track import encode as E
    from track.expr import func_retval

    if isinstance(obj, func_retval):
        return ('call', f'{_helper_name(obj.func)}() -> '
                        f'{_hex(_value(model, ctx, obj))}')

    if isinstance(obj, E.MapLookup):
        hit = _lookup_hit(model, ctx, obj, block)
        return ('call', f'bpf_map_lookup_elem({_slot(model, ctx, obj.map_id, obj.map_key)})'
                        f' -> {"hit" if hit else "miss" if hit is not None else "?"}')
    if isinstance(obj, E.XdpBuffLen):
        return ('call', f'bpf_xdp_get_buff_len() -> '
                        f'{_hex(_value(model, ctx, obj.retval))}')
    if isinstance(obj, (E.AdjustHead, E.AdjustMeta)):
        ok = _eval_bool(model, Bool(f'adjust{obj.idx}_ok')) if obj.idx >= 0 else None
        return ('call', f'{_helper_name(obj.imm)}({obj.delta}) -> '
                        f'{"ok" if ok else "failed" if ok is not None else "?"}')
    if isinstance(obj, E.TailCall):
        try:
            took = _eval_bool(model, E.tail_call_taken(
                obj.map_id, obj.index, obj.slot, obj.target, obj.idx,
                obj.map_name).to_z3(ctx.state_at(block)))
        except Exception:
            took = None
        where = obj.map_name or f'map{obj.map_id}'
        at    = '?' if obj.slot is None else obj.slot
        gone  = ('-> ' + obj.target if took else
                 'failed' if took is not None else '-> ?')
        return ('call', f'bpf_tail_call({where}[{at}]) {gone}')
    if isinstance(obj, E.perf_event_output):
        return ('call', 'bpf_perf_event_output()')
    if isinstance(obj, E.MapDelete):
        return ('write', f'delete {_slot(model, ctx, obj.map_id, obj.map_key)}')
    if isinstance(obj, E.MapUpdate):
        return ('write', f'{_slot(model, ctx, obj.map_id, obj.map_key)} <= '
                         f'{_hex(_value(model, ctx, obj.value))}  (insert)')
    if isinstance(obj, (E.MapWrite, E.MapAtomicAdd)):
        op = '+=' if isinstance(obj, E.MapAtomicAdd) else '<='
        return ('write', f'{_slot(model, ctx, obj.map_id, obj.map_key)}'
                         f'[{_addr(obj.off, obj.var_off, obj.size)}] {op} '
                         f'{_hex(_value(model, ctx, obj.value))}')
    if isinstance(obj, E.PktWrite):
        return ('write', f'pkt[{_addr(obj.off, obj.var_off, obj.size)}] <= '
                         f'{_hex(_value(model, ctx, obj.value))}')
    if isinstance(obj, (E.BssWrite, E.BssAtomicAdd)):
        op = '+=' if isinstance(obj, E.BssAtomicAdd) else '<='
        return ('write', f'{obj.bss_key}[{_addr(obj.off, obj.var_off, obj.size)}]'
                         f' {op} {_hex(_value(model, ctx, obj.value))}')
    if isinstance(obj, E.CtxWrite):
        return ('write', f'rx_queue_index <= {_hex(_value(model, ctx, obj.value))}')
    return None


def _ops(model, ctx, block) -> list:
    items = [(getattr(v, 'idx', -1), 0, v) for v in block.sources]
    items += [(getattr(a, 'idx', -1), 1, a) for a in block.actions]
    out = []
    for _, _, obj in sorted(items, key=lambda t: (t[0], t[1])):
        try:
            row = _op_row(model, ctx, obj, block.num)
        except Exception:
            row = ('?', _clip(str(obj)))
        if row is not None:
            out.append(row)
    return out


def _ret_str(model, ctx, block) -> str:
    st = ctx.ret_state(block)
    if st is None:
        return ''
    v = _as_long(model, st.r0)
    if v is None:
        return '?'
    return f'{v}' + (f' ({XDP_ACTIONS[v]})' if v in XDP_ACTIONS else '')


def _stages(model, ctx, path, target=None) -> list:
    out, prev = [], None
    for b in path:
        block = ctx.blocks[b] if 0 <= b < len(ctx.blocks) else None
        if block is None:
            continue
        s = Stage(block=b, kind=block.kind, target=(b == target))
        if prev is not None:
            s.frm = prev.block
            pb = ctx.blocks[prev.block]
            if pb.kind == 'branch':
                s.edge = 'taken' if b == pb.succ_t else 'fall'
                if pb.cond is None:
                    s.match = '<unrecorded branch condition>'
                else:
                    cond = _named(str(pb.cond), ctx)
                    s.match = _clip(cond if s.edge == 'taken' else _negate(cond))
        s.ops = _ops(model, ctx, block)
        if block.kind == 'exit':
            s.ret = _ret_str(model, ctx, b)
        out.append(s)
        prev = s
    return out


def build(model, ctx, block, cond, st) -> Witness:
    if model is None:
        return None
    data, n = _packet(model, ctx.init_st)
    return Witness(
        packet=data,
        pkt_len=n,
        maps=_maps(model, ctx),
        helpers=_helpers(model, ctx),
        ctx={
            'ingress_ifindex': _as_long(model, ctx.init_st.ingress),
            'rx_queue_index':  _as_long(model, ctx.init_st.rx_index),
            'egress_ifindex':  _as_long(model, ctx.init_st.egress),
        },
        path=_path(model, ctx),
        failed_atoms=_failed_atoms(model, cond, st) if cond is not None else [],
        _model=model, _fwd=ctx, _target=block,
    )
