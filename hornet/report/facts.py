from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bpf.constants import map_type_name
from track.encode import ARRAY_MAP_TYPES, HASH_MAP_TYPES, PROG_MAP_TYPES
from track.expr import JoinValue, func_retval, map_val, num, pkt_val
from verify.spec import HELPER_IMM, PROTOCOL_FIELDS

_HELPER_NAME = {imm: name for name, imm in HELPER_IMM.items()}
_FIELD_NAME: dict[tuple[int, int], str] = {}
for _name, _pos in PROTOCOL_FIELDS.items():
    _FIELD_NAME.setdefault(_pos, _name)

_MAP_REF = re.compile(r'\bmap(\d+)\b')


def key_name(key_id: int) -> str:
    return f'key{key_id}'


def helper_name(imm: int) -> str:
    return _HELPER_NAME.get(imm, f'helper#{imm}')


def field_name(off: int, size: int) -> Optional[str]:
    return _FIELD_NAME.get((off, size))


@dataclass
class Read:
    kind:     str
    idx:      int
    off:      int
    size:     int
    var_off:  bool = False
    map_name: Optional[str] = None
    map_id:   Optional[int] = None
    map_key:  Optional[str] = None
    field:    Optional[str] = None

    @property
    def text(self) -> str:
        at = f'{self.off:#x}' if not self.var_off else f'<var> + {self.off:#x}'
        rng = at if self.size == 1 else f'{at}:+{self.size}'
        if self.kind == 'pkt':
            return f'pkt[{rng}]' + (f'  ({self.field})' if self.field else '')
        return f'{self.map_name}[{self.map_key}][{rng}]'

    def atom(self) -> Optional[dict]:
        if self.var_off:
            return None
        if self.kind == 'pkt':
            if self.field:
                return {'field': self.field, 'value': 0, 'op': 'eq'}
            return {'offset': self.off, 'size': self.size, 'value': 0, 'op': 'eq'}
        return {'read': {'map': self.map_name, 'offset': self.off,
                         'size': self.size}, 'value': 0, 'op': 'eq'}


@dataclass
class Call:
    idx:      int
    imm:      int
    helper:   str
    returns:  str
    block_num: int = -1
    map_name: Optional[str] = None
    map_id:   Optional[int] = None
    map_key:  Optional[str] = None

    target:   Optional[str] = None

    @property
    def text(self) -> str:
        if self.returns == 'transfer':
            return (f'{self.helper}({self.map_name}[{self.map_key}])'
                    f' -> {self.target}')
        arg = f'({self.map_name}, key={self.map_key})' if self.map_name else '()'
        return f'{self.helper}{arg} -> {self.returns}'

    def atom(self) -> Optional[dict]:
        if self.returns == 'transfer':
            return None
        if self.returns == 'pointer':
            return {'idx': self.idx, 'helper': self.helper, 'returns': 'non_null'}
        return {'idx': self.idx, 'helper': self.helper, 'op': 'eq', 'value': 0}


@dataclass
class BlockFact:
    num:     int
    kind:    str
    start:   int
    end:     int
    preds:   list[int] = field(default_factory=list)
    succ_t:  Optional[int] = None
    succ_f:  Optional[int] = None
    cond:    Optional[str] = None
    reads:   list[Read] = field(default_factory=list)
    calls:   list[Call] = field(default_factory=list)
    writes:  list[str] = field(default_factory=list)
    phis:    int = 0
    ret:     Optional[str] = None
    ret_codes: Optional[list[int]] = None
    prog_entry: Optional[str] = None

    @property
    def interesting(self) -> bool:
        return bool(self.reads or self.calls or self.kind == 'exit'
                    or self.prog_entry)

    @property
    def preds_text(self) -> str:
        head = self.preds[:12]
        rest = len(self.preds) - len(head)
        return ('[' + ', '.join(str(p) for p in head)
                + (f', +{rest} more]' if rest else ']'))

    @property
    def edges(self) -> str:
        out = []
        if self.succ_t is not None: out.append(f'taken->{self.succ_t}')
        if self.succ_f is not None: out.append(f'fall->{self.succ_f}')
        if self.kind == 'exit':     out.append('exit')
        return '  '.join(out)


@dataclass
class MapFact:
    id:          int
    name:        str
    type:        int
    type_name:   str
    key_size:    int
    value_size:  int
    max_entries: int
    flags:       int
    lookups:     list[Call] = field(default_factory=list)
    reads:       list[Read] = field(default_factory=list)
    written:     bool = False

    @property
    def family(self) -> str:
        if self.type in ARRAY_MAP_TYPES: return 'array'
        if self.type in HASH_MAP_TYPES:  return 'hash'
        if self.type in PROG_MAP_TYPES:  return 'prog'
        return 'other'

    @property
    def needs_seed(self) -> bool:
        return self.family == 'hash' and bool(self.lookups)

    targets:  list = field(default_factory=list)
    transfers: list[Call] = field(default_factory=list)

    @property
    def note(self) -> str:
        where = ' '.join(f'b{c.block_num}' for c in self.lookups) if self.lookups else ''
        if self.family == 'prog':
            at = (' '.join(f'b{c.block_num}' for c in self.transfers)
                  or 'nowhere')
            loaded = (', '.join(f'[{s}]={n}' for s, n in sorted(self.targets))
                      or 'nothing loaded (--tail)')
            return f'PROG_ARRAY — {loaded}; tail-called at {at}'
        if not self.lookups:
            return 'never looked up by this program'
        if self.family == 'array':
            return f'ARRAY family — entries always present, no seeding needed ({where})'
        if self.family == 'hash':
            return (f'{self.type_name} — unseeded it is EMPTY, so the lookups at '
                    f'{where} always miss')
        return f'{self.type_name} — lookups at {where}'


@dataclass
class ExitFact:
    block:     int
    ret:       str
    ret_codes: Optional[list[int]]


@dataclass
class ProgFact:
    name:        str
    path:        str
    first_block: int
    last_block:  int
    n_instrs:    int
    slot:        Optional[int] = None
    map_name:    Optional[str] = None

    @property
    def is_main(self) -> bool:
        return self.map_name is None

    @property
    def loaded_at(self) -> str:
        if self.is_main:
            return 'entry'
        at = '?' if self.slot is None else self.slot
        return f'{self.map_name}[{at}]'


@dataclass
class ProgramFacts:
    object_path:  str
    entry:        str
    n_instrs:     int
    n_bytes:      int
    n_blocks:     int
    back_edges:   list[tuple[int, int]]
    maps:         list[MapFact]
    blocks:       list[BlockFact]
    exits:        list[ExitFact]
    helpers:      dict[str, int]
    effects:      dict[str, int]
    pkt_reads:    list[tuple[int, int, Optional[str]]]
    var_off_reads: int
    rodata:       int
    bss:          int
    progs:        list = field(default_factory=list)


    @classmethod
    def collect(cls, prog) -> 'ProgramFacts':
        names = {m['id']: (m.get('name') or f'map{m["id"]}') for m in prog.maps}
        maps  = {m['id']: MapFact(id=m['id'], name=names[m['id']], type=m['type'],
                                  type_name=map_type_name(m['type']),
                                  key_size=m['key_size'], value_size=m['value_size'],
                                  max_entries=m['max_entries'], flags=m['flags'])
                 for m in prog.maps}

        blocks, helpers, effects = [], {}, {}
        for b in prog.blocks:
            bf = _block_fact(b, names)
            blocks.append(bf)
            for c in bf.calls:
                helpers[c.helper] = helpers.get(c.helper, 0) + 1
                if c.map_id in maps and c.imm == HELPER_IMM['bpf_map_lookup_elem']:
                    maps[c.map_id].lookups.append(c)
                if c.map_id in maps and c.returns == 'transfer':
                    maps[c.map_id].transfers.append(c)
            for r in bf.reads:
                if r.map_id in maps:
                    maps[r.map_id].reads.append(r)
            for w in bf.writes:
                effects[w] = effects.get(w, 0) + 1
            for a in b.actions:
                mid = getattr(a, 'map_id', None)
                if mid in maps and getattr(a, 'ret', None) is None:
                    maps[mid].written = True

        regions = list(getattr(prog, 'progs', None) or ())
        progs = []
        for r in regions:
            last = max((b.num for b in prog.blocks if r.contains(b.start)),
                       default=r.entry_block)
            progs.append(ProgFact(
                name=r.name, path=r.path, first_block=r.entry_block,
                last_block=last, n_instrs=r.end - r.start + 1,
                slot=r.slot,
                map_name=(names.get(r.map_id) if r.map_id is not None else None)))
            if r.map_id in maps and not r.is_main:
                maps[r.map_id].targets.append((r.slot, r.name))
            if not r.is_main and 0 <= r.entry_block < len(blocks):
                blocks[r.entry_block].prog_entry = r.name

        back_edges = _back_edges(blocks)

        exits = [ExitFact(block=b.num, ret=str(b.ret_expr),
                          ret_codes=_ret_codes(b.ret_expr))
                 for b in prog.blocks if b.kind == 'exit']

        pkt_reads = sorted({(r.off, r.size) for bf in blocks for r in bf.reads
                            if r.kind == 'pkt' and not r.var_off})
        var_off   = sum(1 for bf in blocks for r in bf.reads if r.var_off)

        return cls(
            object_path=prog.file_path, entry=prog.main_func,
            n_instrs=len(prog.instrs), n_bytes=len(prog.instrs) * 8,
            n_blocks=len(prog.blocks), back_edges=back_edges,
            maps=[maps[i] for i in sorted(maps)], blocks=blocks, exits=exits,
            helpers=helpers, effects=effects,
            pkt_reads=[(o, s, field_name(o, s)) for o, s in pkt_reads],
            var_off_reads=var_off,
            rodata=len(prog.rodata or {}), bss=len(prog.bss or {}),
            progs=progs,
        )


    @property
    def acyclic(self) -> bool:
        return not self.back_edges

    @property
    def ret_codes(self) -> Optional[list[int]]:
        out: set[int] = set()
        for e in self.exits:
            if e.ret_codes is None:
                return None
            out.update(e.ret_codes)
        return sorted(out)

    def block(self, num: int) -> Optional[BlockFact]:
        return next((b for b in self.blocks if b.num == num), None)

    def interesting_blocks(self) -> list[BlockFact]:
        return [b for b in self.blocks if b.interesting]

    def packet_template(self) -> str:
        depth = max((o + s for o, s, _ in self.pkt_reads), default=0)
        proto = {(23, 1)}
        has_l4 = depth > 34 or any((o, s) in proto for o, s, _ in self.pkt_reads)
        layers = ['Ether()']
        if depth > 14:
            layers.append('IP()')
        if has_l4 and depth > 34:
            layers.append('TCP()')
        return '/'.join(layers)


def _render(expr, names: dict[int, str]) -> str:
    return _MAP_REF.sub(lambda m: names.get(int(m.group(1)), m.group(0)), str(expr))


def _block_fact(b, names: dict[int, str]) -> BlockFact:
    reads, calls, writes = [], [], []

    for v in b.sources:
        if isinstance(v, pkt_val):
            reads.append(Read(kind='pkt', idx=v.idx, off=v.off, size=v.size,
                              var_off=v.var_off is not None,
                              field=field_name(v.off, v.size)))
        elif isinstance(v, map_val):
            reads.append(Read(kind='map', idx=v.idx, off=v.off, size=v.size,
                              var_off=v.var_off is not None,
                              map_id=v.map_id, map_name=names.get(v.map_id),
                              map_key=key_name(v.map_key_id)))
        elif isinstance(v, func_retval):
            calls.append(Call(idx=v.idx, imm=v.imm, helper=helper_name(v.imm),
                              returns='scalar',
                              map_id=v.map_id, map_name=names.get(v.map_id),
                              map_key=(key_name(v.map_key_id)
                                       if v.map_key is not None else None)))

    for a in b.actions:
        if getattr(a, 'ret', None) is not None:
            mid = getattr(a, 'map_id', None)
            transfer = a.ret == 'transfer'
            calls.append(Call(idx=a.idx, imm=a.imm, helper=helper_name(a.imm),
                              returns=(a.ret if a.ret in ('transfer', 'scalar')
                                       else 'pointer'),
                              map_id=mid,
                              map_name=names.get(mid) if mid is not None else None,
                              map_key=(getattr(a, 'slot', None) if transfer else
                                       (key_name(a.map_key_id)
                                        if getattr(a, 'map_key', None) is not None
                                        else None)),
                              target=getattr(a, 'target', None)))
        else:
            writes.append(type(a).__name__)

    calls.sort(key=lambda c: c.idx)
    for c in calls:
        c.block_num = b.num

    return BlockFact(
        num=b.num, kind=b.kind, start=b.start, end=b.end, preds=list(b.preds),
        succ_t=b.succ_t, succ_f=b.succ_f,
        cond=_render(b.cond, names) if b.cond is not None else None,
        reads=sorted(reads, key=lambda r: r.idx), calls=calls, writes=writes,
        phis=sum(1 for v in b.sources if isinstance(v, JoinValue)),
        ret=_render(b.ret_expr, names) if b.kind == 'exit' else None,
        ret_codes=_ret_codes(b.ret_expr) if b.kind == 'exit' else None,
    )


def _back_edges(blocks: list[BlockFact]) -> list[tuple[int, int]]:
    succs = {b.num: [s for s in (b.succ_t, b.succ_f) if s is not None]
             for b in blocks}
    back, done, on_stack = [], set(), set()
    stack = [(0, iter(succs.get(0, [])))]
    on_stack.add(0)
    while stack:
        node, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            on_stack.discard(node)
            done.add(node)
            continue
        if nxt in on_stack:
            back.append((node, nxt))
        elif nxt not in done and nxt in succs:
            stack.append((nxt, iter(succs[nxt])))
            on_stack.add(nxt)
    return back


def _ret_codes(expr) -> Optional[list[int]]:
    leaves = _leaves(expr, set())
    if leaves is None or not leaves:
        return None
    return sorted(leaves)


def _leaves(expr, seen: set) -> Optional[set[int]]:
    if id(expr) in seen:
        return set()
    seen.add(id(expr))
    if isinstance(expr, JoinValue):
        out: set[int] = set()
        for child in expr.values:
            sub = _leaves(child, seen)
            if sub is None:
                return None
            out |= sub
        return out
    if isinstance(expr, num):
        return {expr.num}
    if isinstance(expr, int):
        return {expr}
    return None
