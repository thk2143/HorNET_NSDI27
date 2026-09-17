from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from z3 import (
    BitVec, BitVecVal, And, Concat, Extract, Not, Or, Select,
    UGT, UGE, ULT, ULE,
)

from track.encode import BPF_MAP_TYPE_PROG_ARRAY


PROTOCOL_FIELDS: dict[str, tuple[int, int]] = {
    'eth_dst':   (0,  6),
    'eth_src':   (6,  6),
    'eth_type':  (12, 2),
    'ip_ver':    (14, 1),
    'ip_tos':    (15, 1),
    'ip_len':    (16, 2),
    'ip_id':     (18, 2),
    'ip_flags':  (20, 2),
    'ip_ttl':    (22, 1),
    'ip_proto':  (23, 1),
    'ip_chk':    (24, 2),
    'ip_src':    (26, 4),
    'ip_dst':    (30, 4),
    'tcp_sport': (34, 2),
    'tcp_dport': (36, 2),
    'udp_sport': (34, 2),
    'udp_dport': (36, 2),
}

HELPER_IMM = {
    'bpf_map_lookup_elem':       1,
    'bpf_ktime_get_ns':          5,
    'bpf_get_prandom_u32':       7,
    'bpf_get_smp_processor_id':  8,
    'bpf_tail_call':            12,
    'bpf_get_current_pid_tgid': 14,
    'bpf_get_current_uid_gid':  15,
    'bpf_redirect':             23,
    'bpf_get_numa_node_id':     42,
    'bpf_csum_diff':            28,
    'bpf_xdp_adjust_head':      44,
    'bpf_redirect_map':         51,
    'bpf_xdp_adjust_meta':      54,
    'bpf_xdp_adjust_tail':      65,
    'bpf_jiffies64':           118,
    'bpf_ktime_get_boot_ns':   125,
    'bpf_ktime_get_coarse_ns': 160,
    'bpf_xdp_get_buff_len':    188,
    'bpf_ktime_get_tai_ns':    208,
}

NO_RETVAL_HELPERS = frozenset({'bpf_tail_call'})


class SpecError(ValueError):
    pass


def _parse_val_bytes(value, size: int) -> list[int]:
    if isinstance(value, bool):
        raise SpecError(f"boolean is not a byte value: {value!r}")
    if isinstance(value, int):
        return list(value.to_bytes(size, 'big'))
    if isinstance(value, (list, tuple)):
        if len(value) != size:
            raise SpecError(f"byte list {value!r} does not match size {size}")
        return [int(b) & 0xFF for b in value]
    if isinstance(value, str):
        v = value.strip()
        if v[:2].lower() == '0x':
            return list(int(v, 16).to_bytes(size, 'big'))
        if '.' in v:
            parts = [int(b) for b in v.split('.')]
            if len(parts) != size:
                raise SpecError(f"IPv4 {v!r} does not match size {size}")
            return parts
        if ':' in v:
            parts = [int(b, 16) for b in v.split(':')]
            if len(parts) != size:
                raise SpecError(f"MAC {v!r} does not match size {size}")
            return parts
        return list(int(v).to_bytes(size, 'big'))
    raise SpecError(f"unparseable value {value!r}")


def _parse_multibyte_int(value, size: int) -> int:
    return int.from_bytes(bytes(_parse_val_bytes(value, size)), 'little')


def _parse_int(x) -> int:
    if isinstance(x, bool):
        raise SpecError(f"boolean is not an int: {x!r}")
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        return int(s, 16) if s[:2].lower() == '0x' else int(s)
    raise SpecError(f"expected int, got {x!r}")


_SCAPY_LAYER_NAMES = (
    'Ether', 'Dot1Q', 'ARP',
    'IP', 'IPv6', 'TCP', 'UDP', 'ICMP', 'ICMPv6EchoRequest',
    'Raw',
)


def _scapy_namespace() -> dict:
    try:
        import scapy.all as _scapy
    except ImportError as e:
        raise SpecError("input.packet requires the 'scapy' package "
                        "(pip install scapy)") from e
    return {name: getattr(_scapy, name) for name in _SCAPY_LAYER_NAMES
            if hasattr(_scapy, name)}


def _eval_scapy_packet(expr: str):
    try:
        pkt = eval(expr, {'__builtins__': {}}, _scapy_namespace())
    except SpecError:
        raise
    except Exception as e:
        raise SpecError(f"could not evaluate packet expression {expr!r}: {e}") from e
    from scapy.packet import Packet
    if not isinstance(pkt, Packet):
        raise SpecError(f"packet expression {expr!r} did not evaluate to a scapy Packet")
    return pkt


def _layer_byte_facts(layer) -> tuple[bytes, list[bool]]:
    p = b""
    group_explicit = True
    mask: list[bool] = []
    for f in layer.fields_desc:
        val = layer.getfieldval(f.name)
        explicit = f.name in layer.fields
        before = len(p) if isinstance(p, bytes) else len(p[0])
        p = f.addfield(layer, p, val)
        group_explicit = group_explicit and explicit
        if isinstance(p, bytes):
            mask.extend([group_explicit] * (len(p) - before))
            group_explicit = True
    if not isinstance(p, bytes):
        raise SpecError(f"layer {layer.__class__.__name__} has an unaligned "
                        f"bitfield header (internal scapy layout assumption violated)")
    return p, mask


def _packet_byte_facts(pkt) -> tuple[bytes, list[bool]]:
    from scapy.packet import NoPayload
    out_bytes, out_mask = b"", []
    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        p, mask = _layer_byte_facts(layer)
        out_bytes += p
        out_mask  += mask
        layer = layer.payload
    return out_bytes, out_mask


@dataclass
class InputSpec:
    pkt_bytes:  dict
    pkt_len:    Optional[int]
    map_values: dict
    ingress_ifindex: Optional[int] = None
    rx_queue_index:  Optional[int] = None
    egress_ifindex:  Optional[int] = None


def _parse_input(node: dict, maps: list) -> InputSpec:
    pkt_bytes: dict = {}
    pkt_len = None
    if 'packet' in node:
        pkt = _eval_scapy_packet(node['packet'])
        ref_bytes, mask = _packet_byte_facts(pkt)
        pkt_bytes = {i: ref_bytes[i] for i, explicit in enumerate(mask) if explicit}
        pkt_len = len(ref_bytes)

    ctx = node.get('context', {}) or {}
    if 'pkt_len' in ctx:
        declared_len = _parse_int(ctx['pkt_len'])
        if pkt_len is not None and declared_len < pkt_len:
            raise SpecError(f"context.pkt_len={declared_len} is shorter than the "
                            f"scapy packet's own length ({pkt_len})")
        pkt_len = declared_len

    map_values: dict = {}
    for ref, entries in (node.get('maps') or {}).items():
        if isinstance(ref, str) and ref.startswith('_'):
            continue
        ref_key = int(ref) if isinstance(ref, str) and ref.lstrip('-').isdigit() else ref
        m = _resolve_map(ref_key, maps)
        if m['type'] == BPF_MAP_TYPE_PROG_ARRAY:
            raise SpecError(
                f"map {m['name']!r} is a PROG_ARRAY: it holds PROGRAMS, not "
                "values, so its contents come from --tail OBJ:ENTRY@SLOT "
                "rather than from input.maps.")
        kv = {}
        for key, value in (entries or {}).items():
            k_int = _parse_multibyte_int(key, m['key_size'])
            v_int = _parse_multibyte_int(value, m['value_size'])
            kv[k_int] = v_int
        map_values[m['id']] = kv

    def _ctx_int(name):
        return _parse_int(ctx[name]) if name in ctx else None

    return InputSpec(
        pkt_bytes=pkt_bytes, pkt_len=pkt_len, map_values=map_values,
        ingress_ifindex=_ctx_int('ingress_ifindex'),
        rx_queue_index=_ctx_int('rx_queue_index'),
        egress_ifindex=_ctx_int('egress_ifindex'),
    )


def z3_state_from_input(input_spec: InputSpec, maps: list):
    from z3 import Array, BitVecSort, BoolSort, BoolVal, K, Store
    from track.encode import _make_init_state, PKT_ADDR_BITS

    pkt0 = Array('pkt0', BitVecSort(PKT_ADDR_BITS), BitVecSort(8))
    for off, val in input_spec.pkt_bytes.items():
        pkt0 = Store(pkt0, BitVecVal(off, PKT_ADDR_BITS), BitVecVal(val, 8))

    map0 = []
    for m in maps:
        Key = BitVecSort(max(m['key_size'], 1) * 8)
        Val = BitVecSort(max(m['value_size'], 1) * 8)
        entries = input_spec.map_values.get(m['id'])
        value   = Array(f"value{m['id']}", Key, Val)
        if entries is None:
            present = Array(f"present{m['id']}", Key, BoolSort())
        else:
            present = K(Key, BoolVal(False))
            for k, v in entries.items():
                kk = BitVecVal(k, Key.size())
                present = Store(present, kk, BoolVal(True))
                value   = Store(value, kk, BitVecVal(v, Val.size()))
        map0.append([present, value])

    def _scalar(name, val):
        return BitVecVal(val, 64) if val is not None else BitVec(name, 64)

    return _make_init_state(
        maps,
        pkt0=pkt0, map0=map0,
        rx_index0=_scalar('rx_queue_index0', input_spec.rx_queue_index),
        ingress=_scalar('ingress_ifindex',   input_spec.ingress_ifindex),
        egress=_scalar('egress_ifindex',     input_spec.egress_ifindex),
        pkt_len_val=(BitVecVal(input_spec.pkt_len, 64)
                     if input_spec.pkt_len is not None else None),
    )


@dataclass
class PktAtom:
    offset: int
    size:   int
    data:   list
    op:     str = 'eq'

    def to_z3(self, st):
        if st.read_loc is not None:
            eq = And(*[st.read_loc(0, self.offset + i, 1, None, None) ==
                       BitVecVal(self.data[i], 8) for i in range(self.size)])
            return eq if self.op == 'eq' else Not(eq)
        dom = st.pkt.domain().size()
        eq = And(*[Select(st.pkt, BitVecVal(self.offset + i, dom)) ==
                   BitVecVal(self.data[i], 8) for i in range(self.size)])
        return eq if self.op == 'eq' else Not(eq)


@dataclass
class MapAtom:
    map_id:  int
    key:     int
    present: Optional[bool] = None
    value:   Optional[int]  = None
    key_size:   int = 8
    value_size: int = 8

    def to_z3(self, st):
        from track.expr import num
        from track.encode import contain_map_value
        k = BitVecVal(self.key, self.key_size * 8)
        key_expr = num(num=self.key, size=self.key_size)
        present = contain_map_value(self.map_id, key_expr, None, True).to_z3(st)
        if self.value is not None:
            if st.read_loc is not None:
                parts = [st.read_loc(1, i, 1, self.map_id, key_expr)
                         for i in reversed(range(self.value_size))]
                got = Concat(*parts) if len(parts) > 1 else parts[0]
                return And(present, got == BitVecVal(self.value,
                                                     self.value_size * 8))
            return And(present,
                       st.map[self.map_id][1][k] == BitVecVal(self.value,
                                                              self.value_size * 8))
        return present if self.present else Not(present)


@dataclass
class BssAtom:
    sym:    str
    offset: int
    size:   int
    value:  int
    op:     str = 'eq'

    def to_z3(self, st):
        from track.record import BSS
        if st.read_loc is not None:
            got = [st.read_loc(BSS, self.offset + i, 1, None, None, bss_key=self.sym)
                   for i in range(self.size)]
        else:
            from track.encode import _bss_of, BSS_ADDR_BITS
            arr = _bss_of(st, self.sym)
            got = [Select(arr, BitVecVal(self.offset + i, BSS_ADDR_BITS))
                   for i in range(self.size)]
        got.reverse()
        whole = Concat(*got) if len(got) > 1 else got[0]
        eq = whole == BitVecVal(self.value, self.size * 8)
        return eq if self.op == 'eq' else Not(eq)


@dataclass
class LenAtom:
    min: Optional[int] = None
    max: Optional[int] = None

    def to_z3(self, st):
        parts = []
        if self.min is not None:
            parts.append(UGE(st.pkt_len, BitVecVal(self.min, 64)))
        if self.max is not None:
            parts.append(ULE(st.pkt_len, BitVecVal(self.max, 64)))
        return And(*parts) if len(parts) > 1 else parts[0]


@dataclass
class ScalarAtom:
    target: str
    value:  int

    def to_z3(self, st):
        field_z3 = {'ingress': st.ingress, 'rx_index': st.rx_index,
                    'egress': st.egress}[self.target]
        return field_z3 == BitVecVal(self.value, 64)


@dataclass
class HelperAtom:
    kind:   str
    imm:    int
    idx:    int
    size:   int = 8
    op:     str = None
    value:  int = None
    result: bool = None
    retval: object = None
    map_id:     int = None
    map_key:    object = None
    map_key_id: int = None

    def to_z3(self, st):
        if self.kind == 'scalar':
            from track.encode import expr_to_z3
            v   = expr_to_z3(self.retval, st)
            rhs = BitVecVal(self.value, v.size())
            return {
                'eq': lambda: v == rhs,   'ne': lambda: v != rhs,
                'lt': lambda: ULT(v, rhs), 'le': lambda: ULE(v, rhs),
                'gt': lambda: UGT(v, rhs), 'ge': lambda: UGE(v, rhs),
            }[self.op]()
        from track.encode import contain_map_value
        return contain_map_value(self.map_id, self.map_key,
                                 self.map_key_id, self.result).to_z3(st)


@dataclass
class RetAtom:
    op:    str
    value: int

    def to_z3(self, st):
        rhs = BitVecVal(self.value, 64)
        return {
            'eq': lambda: st.r0 == rhs,  'ne': lambda: st.r0 != rhs,
            'lt': lambda: ULT(st.r0, rhs), 'le': lambda: ULE(st.r0, rhs),
            'gt': lambda: UGT(st.r0, rhs), 'ge': lambda: UGE(st.r0, rhs),
        }[self.op]()


@dataclass
class ReadAtom:
    parts:      Any
    op:         str
    target:     int
    size:       int
    region:     int
    offset:     int = 0
    map_id:     Optional[int] = None

    def to_z3(self, st):
        from track.encode import expr_to_z3
        bs = [Extract(k * 8 + 7, k * 8, expr_to_z3(leaf, st)) for leaf, k in self.parts]
        bs.reverse()
        v = Concat(*bs) if len(bs) > 1 else bs[0]
        rhs = BitVecVal(self.target, v.size())
        return v == rhs if self.op == 'eq' else v != rhs


@dataclass
class CondNode:
    op:       str
    atom:     Any = None
    children: list = field(default_factory=list)

    def to_z3(self, st):
        if self.op == 'leaf':
            return self.atom.to_z3(st)
        if self.op == 'not':
            return Not(self.children[0].to_z3(st))
        terms = [c.to_z3(st) for c in self.children]
        return And(*terms) if self.op == 'and' else Or(*terms)


@dataclass
class BlockCondition:
    name:        str
    block:       int
    assert_mode: str
    cond:        CondNode


@dataclass
class ExitCondition:
    name:        str
    assert_mode: str
    cond:        CondNode


@dataclass
class Policy:
    input:            Optional[InputSpec] = None
    block_conditions: dict = field(default_factory=dict)
    exit_conditions:  dict = field(default_factory=dict)


_CTX_TARGETS = {
    'ingress_ifindex': 'ingress',
    'rx_queue_index':  'rx_index',
    'egress_ifindex':  'egress',
}


def _resolve_map(ref, maps) -> dict:
    if maps is None:
        raise SpecError("map reference used but no `maps` provided to load_spec")
    for m in maps:
        if ref == m['id'] or ref == m['name']:
            return m
    avail = [(m['id'], m['name']) for m in maps]
    raise SpecError(f"map {ref!r} not found (available: {avail})")


def _parse_helper_atom(a: dict, calls) -> HelperAtom:
    if calls is None:
        raise SpecError("helper atom used but no `calls` provided to load_spec")
    idx = _parse_int(a['idx'])
    rec = calls.get(idx)
    if rec is None:
        raise SpecError(f"idx {idx} is not a recorded helper call "
                        f"(available: {sorted(calls)})")
    if rec.ret == 'transfer':
        raise SpecError(
            f"idx {idx} is a bpf_tail_call, which has no return value to name "
            "on the path a spec cares about: on success it transfers control "
            "and never returns. Ask about the transfer with a block_condition "
            "on the callee's entry block instead.")
    if 'helper' in a:
        want = HELPER_IMM.get(a['helper'])
        if want is None:
            raise SpecError(f"unknown helper {a['helper']!r}")
        if want != rec.imm:
            raise SpecError(f"idx {idx} is helper imm {rec.imm}, "
                            f"not {a['helper']!r} (imm {want})")
    if rec.ret == 'scalar':
        if 'op' not in a or 'value' not in a:
            raise SpecError(f"scalar helper atom needs 'op' and 'value': {a!r}")
        if a['op'] not in ('eq', 'ne', 'lt', 'le', 'gt', 'ge'):
            raise SpecError(f"invalid helper op {a['op']!r}")
        return HelperAtom(kind='scalar', imm=rec.imm, idx=idx,
                          size=rec.ret_size, op=a['op'],
                          value=_parse_int(a['value']),
                          retval=getattr(rec, 'retval', rec))
    ret = a.get('returns')
    if ret not in ('null', 'non_null'):
        raise SpecError(f"pointer helper atom needs returns: null|non_null: {a!r}")
    return HelperAtom(kind='map_null',
                      imm=rec.imm, idx=idx, result=(ret == 'non_null'),
                      map_id=rec.map_id, map_key=rec.map_key,
                      map_key_id=rec.map_key_id)


def _parse_atom(a: dict, maps, calls, block=None, blocks=None) -> Any:
    if not isinstance(a, dict):
        raise SpecError(f"atom must be an object, got {a!r}")

    if 'idx' in a:
        return _parse_helper_atom(a, calls)

    if 'ret' in a:
        if block is not None:
            raise SpecError(
                "a 'ret' atom is only valid in exit_conditions — r0 is not "
                f"bound at block {block}, so the condition would name a free "
                "variable rather than the program's return value")
        op = a.get('op', 'eq')
        if op not in ('eq', 'ne', 'lt', 'le', 'gt', 'ge'):
            raise SpecError(f"invalid ret op {op!r}")
        return RetAtom(op=op, value=_parse_int(a['ret']))

    if 'read' in a:
        return _parse_read_atom(a, maps, block, blocks)

    op = a.get('op', 'eq')
    if op not in ('eq', 'ne'):
        raise SpecError(f"invalid op {op!r} (expected 'eq'|'ne')")

    if 'bss' in a:
        if not isinstance(a['bss'], str):
            raise SpecError(f"bss atom names a symbol by string: {a!r}")
        if 'size' not in a or 'value' not in a:
            raise SpecError(f"bss atom needs 'size' and 'value': {a!r}")
        size = int(a['size'])
        if size < 1:
            raise SpecError(f"bss atom size must be at least 1: {a!r}")
        return BssAtom(sym=a['bss'], offset=int(a.get('offset', 0)), size=size,
                       value=_parse_multibyte_int(a['value'], size), op=op)

    if 'map' in a:
        m = _resolve_map(a['map'], maps)
        present = a.get('contains')
        value   = a.get('value')
        if present is None and value is None:
            raise SpecError(f"map atom needs 'contains' or 'value': {a!r}")
        if value is not None and present is False:
            raise SpecError(
                f"map atom cannot ask for 'contains': false and a 'value' at "
                f"once — an absent key has no value: {a!r}")
        return MapAtom(map_id=m['id'],
                       key=_parse_multibyte_int(a['key'], m['key_size']),
                       present=(bool(present) if present is not None else None),
                       value=(_parse_multibyte_int(value, m['value_size'])
                              if value is not None else None),
                       key_size=m['key_size'], value_size=m['value_size'])

    if 'pkt_len' in a:
        r = a['pkt_len']
        return LenAtom(min=r.get('min'), max=r.get('max'))

    if 'ctx' in a:
        tgt = _CTX_TARGETS.get(a['ctx'])
        if tgt is None:
            raise SpecError(f"unknown ctx target {a['ctx']!r}")
        return ScalarAtom(target=tgt, value=_parse_int(a['value']))

    if 'field' in a:
        if a['field'] not in PROTOCOL_FIELDS:
            raise SpecError(f"unknown field {a['field']!r}")
        offset, size = PROTOCOL_FIELDS[a['field']]
    elif 'offset' in a and 'size' in a:
        offset, size = int(a['offset']), int(a['size'])
    else:
        raise SpecError(f"unrecognized atom shape: {a!r}")
    if 'value' not in a:
        raise SpecError(f"packet atom needs 'value': {a!r}")
    return PktAtom(offset=offset, size=size,
                   data=_parse_val_bytes(a['value'], size), op=op)


def _const_off(off) -> Optional[int]:
    if isinstance(off, int):
        return off
    from track.expr import num as _num
    return off.num if isinstance(off, _num) else None


def _byte_index(sources, region: int, map_id=None) -> dict:
    from track.expr import pkt_val, map_val
    want = pkt_val if region == 0 else map_val
    out: dict[int, Any] = {}
    for v in sources:
        if not isinstance(v, want):
            continue
        if region == 0 and v.var_off is not None:
            continue
        if region == 1 and v.map_id != map_id:
            continue
        for i in range(v.size):
            out[v.off + i] = (v, i)
    return out


def _assemble(sources, region: int, offset: int, size: int, map_id=None):
    index = _byte_index(sources, region, map_id)
    parts = [index.get(o) for o in range(offset, offset + size)]
    return None if any(p is None for p in parts) else parts


def _parse_read_atom(a: dict, maps, block, blocks) -> ReadAtom:
    if block is None:
        raise SpecError("a 'read' atom needs a specific block — "
                        "not valid inside exit_conditions")
    if blocks is None:
        raise SpecError("a 'read' atom needs `blocks` "
                        "(pass blocks=... to load_spec)")
    if not 0 <= block < len(blocks):
        raise SpecError(f"a 'read' atom's block {block} is not a tracked block "
                        f"(0..{len(blocks) - 1})")

    spec = a['read']
    if not isinstance(spec, dict):
        raise SpecError(f"'read' must be an object: {a!r}")
    op = a.get('op', 'eq')
    if op not in ('eq', 'ne'):
        raise SpecError(f"invalid read op {op!r} (expected 'eq'|'ne')")
    if 'value' not in a:
        raise SpecError(f"read atom needs 'value': {a!r}")
    if 'size' not in spec:
        raise SpecError(f"'read' needs 'size': {a!r}")
    size = int(spec['size'])

    sources = blocks[block].sources
    if 'map' in spec:
        m      = _resolve_map(spec['map'], maps)
        offset = int(spec.get('offset', 0))
        region, map_id = 1, m['id']
        where  = f"map {spec['map']!r} offset {offset} size {size} in block {block}"
    elif 'offset' in spec:
        offset = int(spec['offset'])
        region, map_id = 0, None
        where  = f"packet offset {offset} size {size} in block {block}"
    else:
        raise SpecError(f"'read' needs 'offset'+'size' (packet) or "
                        f"'map'+'size' (map value): {a!r}")

    parts = _assemble(sources, region, offset, size, map_id)
    if parts is None:
        from track.expr import pkt_val, map_val
        n = sum(1 for s in sources if isinstance(s, (pkt_val, map_val)))
        raise SpecError(f"block {block} never read some byte of {where} — hornet "
                        f"only tracks reads that actually execute on this "
                        f"block's own path ({n} read(s) recorded there)")

    target = _parse_multibyte_int(a['value'], size)
    return ReadAtom(parts=parts, op=op, target=target,
                    size=size, region=region, offset=offset, map_id=map_id)


_COND_COMBINATORS = ('and', 'or', 'not')


def _parse_cond(node, maps, calls, block=None, blocks=None) -> CondNode:
    if isinstance(node, dict) and len(node) == 1 and next(iter(node)) in _COND_COMBINATORS:
        op, kids = next(iter(node.items()))
        if op == 'not':
            if isinstance(kids, list):
                if len(kids) != 1:
                    raise SpecError("'not' takes exactly one child condition")
                kids = kids[0]
            return CondNode(op='not',
                            children=[_parse_cond(kids, maps, calls, block, blocks)])
        if not isinstance(kids, list):
            raise SpecError(f"'{op}' needs a list of child conditions")
        if not kids:
            return CondNode(op='and', children=[])
        return CondNode(op=op, children=[_parse_cond(k, maps, calls, block, blocks)
                                        for k in kids])
    return CondNode(op='leaf', atom=_parse_atom(node, maps, calls, block, blocks))


def _parse_block_condition(name, node, maps, blocks, calls) -> BlockCondition:
    if 'block' not in node:
        raise SpecError(f"block_conditions[{name!r}] needs a 'block'")
    block = int(node['block'])
    if blocks is not None and not 0 <= block < len(blocks):
        raise SpecError(f"block_conditions[{name!r}]: block {block} is not a "
                        f"tracked block (0..{len(blocks) - 1})")
    mode = node.get('assert', 'exists')
    if mode not in ('all', 'exists'):
        raise SpecError(f"block_conditions[{name!r}]: invalid assert {mode!r}")
    cond = _parse_cond(node.get('cond', {'and': []}), maps, calls, block, blocks)
    return BlockCondition(name=name, block=block, assert_mode=mode, cond=cond)


def _parse_exit_condition(name, node, maps, calls) -> ExitCondition:
    mode = node.get('assert', 'exists')
    if mode not in ('all', 'exists'):
        raise SpecError(f"exit_conditions[{name!r}]: invalid assert {mode!r}")
    cond = _parse_cond(node.get('cond', {'and': []}), maps, calls)
    return ExitCondition(name=name, assert_mode=mode, cond=cond)


_TOP_LEVEL_KEYS = frozenset({'input', 'block_conditions', 'exit_conditions'})


def load_spec(path: str, maps: list = None, blocks: list = None,
              calls: dict = None) -> Policy:
    with open(path) as f:
        raw = json.load(f)
    return parse_spec(raw, maps=maps, blocks=blocks, calls=calls)


def parse_spec(raw: dict, maps: list = None, blocks: list = None,
               calls: dict = None) -> Policy:
    if not isinstance(raw, dict):
        raise SpecError("top level must be an object")
    unknown = {k for k in raw if not k.startswith('_')} - _TOP_LEVEL_KEYS
    if unknown:
        raise SpecError(f"unknown top-level key(s) {sorted(unknown)!r} "
                        f"(expected a subset of {sorted(_TOP_LEVEL_KEYS)!r})")
    if not (_TOP_LEVEL_KEYS & set(raw)):
        raise SpecError("spec has none of 'input'/'block_conditions'/'exit_conditions'")

    input_spec = _parse_input(raw['input'], maps) if 'input' in raw else None
    block_conditions = {
        name: _parse_block_condition(name, node, maps, blocks, calls)
        for name, node in (raw.get('block_conditions') or {}).items()
        if not name.startswith('_')
    }

    if os.environ.get('HORNET_SPEC_DEBUG'):
        for name, node in block_conditions.items():
            print(f"block_conditions[{name!r}]: block {node.block}, "
                  f"assert {node.assert_mode}")
            print(f"  cond: {node.cond}")

    exit_conditions = {
        name: _parse_exit_condition(name, node, maps, calls)
        for name, node in (raw.get('exit_conditions') or {}).items()
        if not name.startswith('_')
    }
    return Policy(input=input_spec, block_conditions=block_conditions,
                 exit_conditions=exit_conditions)
