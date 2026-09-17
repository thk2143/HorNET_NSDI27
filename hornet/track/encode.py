from __future__ import annotations

from dataclasses import dataclass

from z3 import (
    BitVec, BitVecVal, BitVecSort, Array, Bool, BoolSort, BoolVal, K, Store,
    And, Or, Not, If, Select, Concat, Extract,
    UGT, UGE, ULT, ULE, LShR, UDiv, URem, SRem, SignExt, is_bv_value,
)

from bpf.constants import (
    ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR, MOV, ARSH, END,
    JEQ, JNE, JGT, JGE, JLT, JLE, JSGT, JSGE, JSLT, JSLE, JSET,
    S_REG, branch_op_to_str,
)
from track.expr import (
    Expr, Scalar, num, ByteSeq, ALUunary, ALUbinary,
    PTR, PTR_TO_PKT, PTR_TO_PKT_END,
    pkt_len, pkt_val, map_val, bss_val, rodata_val, lookup_hit, func_retval,
    ingress_ifindex, rx_queue_index, egress_ifindex,
    JoinValue,
)
from track.record import PKT, MAP, CTX, BSS


BPF_MAP_TYPE_HASH            = 1
BPF_MAP_TYPE_ARRAY           = 2
BPF_MAP_TYPE_PROG_ARRAY      = 3
BPF_MAP_TYPE_PERCPU_HASH     = 5
BPF_MAP_TYPE_PERCPU_ARRAY    = 6
BPF_MAP_TYPE_LRU_HASH        = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH = 10

ARRAY_MAP_TYPES = frozenset({BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY})
HASH_MAP_TYPES  = frozenset({BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_HASH,
                              BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH})
PROG_MAP_TYPES  = frozenset({BPF_MAP_TYPE_PROG_ARRAY})

EINVAL = 22


def _map_info(st, map_id):
    meta = getattr(st, 'map_meta', None)
    if not meta or map_id is None or map_id < 0 or map_id >= len(meta):
        return None
    return meta[map_id]


def _is_array_map(st, map_id):
    info = _map_info(st, map_id)
    return info is not None and info.get('type') in ARRAY_MAP_TYPES


def _is_hash_map(st, map_id):
    info = _map_info(st, map_id)
    return info is not None and info.get('type') in HASH_MAP_TYPES


def _is_prog_map(st, map_id):
    info = _map_info(st, map_id)
    return info is not None and info.get('type') in PROG_MAP_TYPES


PKT_ADDR_BITS = 16

BSS_ADDR_BITS = 16

RODATA_ADDR_BITS = 32

_RODATA_ARRAYS: dict = {}


def _rodata_array(data: bytes):
    arr = _RODATA_ARRAYS.get(data)
    if arr is None:
        arr = K(BitVecSort(RODATA_ADDR_BITS), BitVecVal(0, 8))
        for i, byte in enumerate(data):
            if byte:
                arr = Store(arr, BitVecVal(i, RODATA_ADDR_BITS), BitVecVal(byte, 8))
        _RODATA_ARRAYS[data] = arr
    return arr


def _byte_of(bv, k: int):
    lo = k * 8
    if lo >= bv.size():
        return BitVecVal(0, 8)
    return _resize(Extract(min(lo + 8, bv.size()) - 1, lo, bv), 8)


def _resize(bv, bits):
    if bv.size() == bits:
        return bv
    if bv.size() > bits:
        return Extract(bits - 1, 0, bv)
    return Concat(BitVecVal(0, bits - bv.size()), bv)


def _bits_used(bv) -> int:
    if is_bv_value(bv):
        return max(bv.as_long().bit_length(), 1)
    return bv.size()


def _alu64_width(op, dst, src) -> int:
    a, b = _bits_used(dst), _bits_used(src)
    if op == ADD:
        bits = max(a, b) + 1
    elif op == MUL:
        bits = a + b
    elif op == LSH and is_bv_value(src):
        bits = a + src.as_long()
    elif op in (SUB, LSH):
        bits = 64
    else:
        bits = max(dst.size(), src.size())
    return min(64, max(8, -(-bits // 8) * 8))


def _splice_bytes(cur, offset, size, val):
    width  = cur.size()
    lo, hi = offset * 8, (offset + size) * 8
    if lo >= width:
        return cur
    hi  = min(hi, width)
    val = _resize(val, hi - lo)
    parts = []
    if hi < width:
        parts.append(Extract(width - 1, hi, cur))
    parts.append(val)
    if lo > 0:
        parts.append(Extract(lo - 1, 0, cur))
    return Concat(*parts) if len(parts) > 1 else parts[0]


def _extract_bytes_var(cur, offset, size):
    width = cur.size()
    shift = _resize(offset, width) * 8
    return _resize(LShR(cur, shift), size * 8)


def _splice_bytes_var(cur, offset, size, val):
    width   = cur.size()
    shift   = _resize(offset, width) * 8
    mask    = _resize(BitVecVal((1 << (size * 8)) - 1, size * 8), width) << shift
    patched = (_resize(val, width) << shift) & mask
    return (cur & ~mask) | patched


def _map_store(st, map_id, key, new_val, mark_present):
    new_map = [list(m) for m in st.map]
    new_map[map_id][1] = Store(st.map[map_id][1], key, new_val)
    if mark_present and _is_hash_map(st, map_id):
        new_map[map_id][0] = Store(st.map[map_id][0], key, BoolVal(True))
    return Z3State(map=new_map, st=st)


def pkt_size_check(dst_value, src_value) -> bool:
    if not (isinstance(dst_value, PTR) and isinstance(src_value, PTR)):
        return False
    types = {dst_value.ptr_type, src_value.ptr_type}
    if not types == {PTR_TO_PKT, PTR_TO_PKT_END}:
        return False
    if dst_value.base_id != src_value.base_id:
        return False
    return True


class Z3State:

    map_meta = None

    read_pkt = None
    read_map = None
    read_bss = None

    read_fret = None

    read_phi = None

    read_loc = None
    at_block = None

    read_present = None

    def __init__(self, pkt=None, map=None, r0=None,
                 rx_index=None, ingress=None, egress=None, pkt_len=None,
                 bss=None,
                 read_pkt=None, read_map=None, read_phi=None, read_loc=None,
                 read_present=None, read_bss=None, read_fret=None,
                 at_block=None, st=None):
        self.read_pkt  = (read_pkt if read_pkt is not None
                          else getattr(st, 'read_pkt', None))
        self.read_map  = (read_map if read_map is not None
                          else getattr(st, 'read_map', None))
        self.read_bss  = (read_bss if read_bss is not None
                          else getattr(st, 'read_bss', None))
        self.read_fret = (read_fret if read_fret is not None
                          else getattr(st, 'read_fret', None))
        self.read_phi  = (read_phi if read_phi is not None
                          else getattr(st, 'read_phi', None))
        self.read_loc  = (read_loc if read_loc is not None
                          else getattr(st, 'read_loc', None))
        self.read_present = (read_present if read_present is not None
                             else getattr(st, 'read_present', None))
        self.at_block  = (at_block if at_block is not None
                          else getattr(st, 'at_block', None))
        self.pkt      = pkt      if pkt      is not None else st.pkt
        self.map      = map      if map      is not None else [list(m) for m in st.map]
        self.r0       = r0       if r0       is not None else st.r0
        self.rx_index = rx_index if rx_index is not None else st.rx_index
        self.ingress  = ingress  if ingress  is not None else st.ingress
        self.egress   = egress   if egress   is not None else st.egress
        self.pkt_len  = pkt_len  if pkt_len  is not None else st.pkt_len
        self.bss      = (dict(bss) if bss is not None
                         else dict(getattr(st, 'bss', None) or {}))


def _bss_of(st, key):
    have = (getattr(st, 'bss', None) or {}).get(key)
    if have is not None:
        return have
    return K(BitVecSort(BSS_ADDR_BITS), BitVecVal(0, 8))


def expr_to_z3(expr, st: Z3State, memo=None):
    if memo is None:
        memo = {}
    if type(expr) in (ALUunary, ALUbinary):
        cached = memo.get(id(expr))
        if cached is not None:
            return cached
    if type(expr) == int:
        return BitVecVal(expr, 64)
    if isinstance(expr, num):
        return BitVecVal(expr.num, expr.size * 8)
    if isinstance(expr, pkt_len):
        return st.pkt_len
    if isinstance(expr, pkt_val):
        got = st.read_pkt(expr) if st.read_pkt is not None else None
        if got is not None:
            return got
        dom  = st.pkt.domain().size()
        base = BitVecVal(expr.off, dom)
        if expr.var_off is not None:
            base = _resize(expr_to_z3(expr.var_off, st, memo), dom) + base
        bs = [Select(st.pkt, base + BitVecVal(i, dom)) for i in range(expr.size)]
        bs.reverse()
        return Concat(*bs) if len(bs) > 1 else bs[0]
    if isinstance(expr, map_val):
        got = st.read_map(expr) if st.read_map is not None else None
        if got is not None:
            return got
        val = Select(st.map[expr.map_id][1],
                     _map_key_z3(st, expr.map_id, expr.map_key, memo))
        if expr.var_off is not None:
            base = (_resize(expr_to_z3(expr.var_off, st, memo), val.size())
                    + BitVecVal(expr.off, val.size()))
            return _extract_bytes_var(val, base, expr.size)
        lo = expr.off * 8
        if lo >= val.size():
            return BitVecVal(0, expr.size * 8)
        return _resize(Extract(min(lo + expr.size * 8, val.size()) - 1, lo, val),
                       expr.size * 8)
    if isinstance(expr, bss_val):
        got = st.read_bss(expr) if st.read_bss is not None else None
        if got is not None:
            return got
        arr = _bss_of(st, expr.bss_key)
        base = BitVecVal(expr.off, BSS_ADDR_BITS)
        if expr.var_off is not None:
            base = _resize(expr_to_z3(expr.var_off, st, memo), BSS_ADDR_BITS) + base
        bs = [Select(arr, base + BitVecVal(i, BSS_ADDR_BITS))
              for i in range(expr.size)]
        bs.reverse()
        return Concat(*bs) if len(bs) > 1 else bs[0]
    if isinstance(expr, rodata_val):
        arr  = _rodata_array(expr.data)
        base = BitVecVal(expr.off, RODATA_ADDR_BITS)
        if expr.var_off is not None:
            base = _resize(expr_to_z3(expr.var_off, st, memo), RODATA_ADDR_BITS) + base
        bs = [Select(arr, base + BitVecVal(i, RODATA_ADDR_BITS))
              for i in range(expr.size)]
        bs.reverse()
        return Concat(*bs) if len(bs) > 1 else bs[0]
    if isinstance(expr, lookup_hit):
        hit = contain_map_value(expr.map_id, expr.map_key,
                                expr.map_key_id, True).to_z3(st)
        return If(hit, BitVecVal(1, 8), BitVecVal(0, 8))
    if isinstance(expr, func_retval):
        if expr.redirects:
            got = st.read_fret(expr) if st.read_fret is not None else None
            if got is not None:
                return got
            w = 8 * expr.size
            if expr.map_id is None:
                return BitVecVal(expr.fallback, w)
            ok = contain_map_value(expr.map_id, expr.map_key,
                                   expr.map_key_id, True).to_z3(st)
            return If(ok, BitVecVal(4, w), BitVecVal(expr.fallback, w))
        if expr.func in (44, 54, 65):
            w = 8 * expr.size
            return If(Bool(f'adjust{expr.idx}_ok'), BitVecVal(0, w),
                      BitVecVal(-EINVAL, w))
        return BitVec(f'func{expr.func}_{expr.idx}', 8 * expr.size)
    if isinstance(expr, ingress_ifindex):
        return st.ingress
    if isinstance(expr, rx_queue_index):
        return st.rx_index
    if isinstance(expr, egress_ifindex):
        return st.egress
    if isinstance(expr, JoinValue):
        return st.read_phi(expr) if st.read_phi is not None else BitVec(
            f'phi{expr.block_idx}_{expr.reg_num}', 64)
    if isinstance(expr, ByteSeq):
        cells = [BitVecVal(0, 64) if c is None
                 else _resize(expr_to_z3(c, st, memo), 64)
                 for c in expr.chunks]
        cells.reverse()
        whole = Concat(*cells) if len(cells) > 1 else cells[0]
        if expr.off:
            whole = LShR(whole, expr.off * 8)
        return _resize(whole, expr.size * 8)
    if isinstance(expr, ALUunary):
        e_dst = expr_to_z3(expr.dst, st, memo)
        if expr.op == NEG:
            res = -_resize(e_dst, 32 if expr.size == 4 else 64)
        elif expr.op == MOV:
            width = 32 if expr.size == 4 else 64
            res = SignExt(width - expr.imm,
                          Extract(expr.imm - 1, 0, _resize(e_dst, 64)))
        elif expr.op == END:
            bits = expr.imm if expr.imm in (16, 32, 64) else 64
            low = Extract(bits - 1, 0, _resize(e_dst, 64))
            if expr.alu64 or expr.opcode_s == S_REG:
                res = Concat(*[Extract(i + 7, i, low) for i in range(0, bits, 8)])
            else:
                res = low
        else:
            raise Exception(f"Unknown unary ALU op: {expr.op}")
        memo[id(expr)] = res
        return res
    if isinstance(expr, ALUbinary):
        e_dst = expr_to_z3(expr.dst, st, memo)
        e_src = expr_to_z3(expr.src, st, memo)
        signed = expr.offset == 1 and expr.op in (DIV, MOD)
        if expr.op in (LSH, RSH, ARSH):
            amt_bits = 5 if expr.size == 4 else 6
            e_src = (BitVecVal(e_src.as_long() & ((1 << amt_bits) - 1), amt_bits)
                     if is_bv_value(e_src)
                     else Extract(amt_bits - 1, 0, _resize(e_src, 64)))
        if expr.size == 4:
            width = 32
        else:
            width = (64 if signed
                     else _alu64_width(expr.op, e_dst, e_src))
        e_dst, e_src = _resize(e_dst, width), _resize(e_src, width)
        if   expr.op == ADD:  res = e_dst + e_src
        elif expr.op == SUB:  res = e_dst - e_src
        elif expr.op == MUL:  res = e_dst * e_src
        elif expr.op == DIV:
            quot = e_dst / e_src if signed else UDiv(e_dst, e_src)
            if is_bv_value(e_src):
                res = BitVecVal(0, width) if e_src.as_long() == 0 else quot
            else:
                res = If(e_src == 0, BitVecVal(0, width), quot)
        elif expr.op == OR:   res = e_dst | e_src
        elif expr.op == AND:  res = e_dst & e_src
        elif expr.op == LSH:  res = e_dst << e_src
        elif expr.op == RSH:  res = LShR(e_dst, e_src)
        elif expr.op == MOD:
            res = SRem(e_dst, e_src) if signed else URem(e_dst, e_src)
        elif expr.op == XOR:  res = e_dst ^ e_src
        elif expr.op == ARSH:
            res = (e_dst >> e_src if width == expr.size * 8
                   else LShR(e_dst, e_src))
        else:
            raise Exception(f"Unknown binary ALU op: {expr.op}")
        memo[id(expr)] = res
        return res
    if type(expr) is Scalar:
        return BitVec(f'scalar{expr.idx}', 8 * expr.size)
    raise Exception(f"expr_to_z3: no encoding for {type(expr).__name__}: {expr}")


def _map_key_z3(st, map_id, map_key, memo=None):
    key = expr_to_z3(map_key, st, memo)
    return _resize(key, st.map[map_id][1].domain().size())


def _ptr_is_null(p: PTR):
    if p.ptr_type == PTR_TO_PKT:
        return False
    return p.checked_null


class Condition:
    def __init__(self, code: int, dst, src, jmp32: bool = False):
        self.code  = code
        self.dst   = dst
        self.src   = src
        self.jmp32 = jmp32

    def __str__(self):
        op = branch_op_to_str[self.code] + ('32' if getattr(self, 'jmp32', False) else '')
        return f"({self.dst} {op} {self.src})"

    _SIGNED = (JSGT, JSGE, JSLT, JSLE)

    def to_z3(self, st: Z3State):
        if self.code in (JEQ, JNE):
            if isinstance(self.dst, PTR):
                ptr, other = self.dst, self.src
            elif isinstance(self.src, PTR):
                ptr, other = self.src, self.dst
            else:
                ptr, other = None, None
            if (ptr is not None and isinstance(other, num) and other.num == 0
                    and _ptr_is_null(ptr) is not None):
                is_null = bool(_ptr_is_null(ptr))
                return BoolVal(is_null if self.code == JEQ else not is_null)

        src = expr_to_z3(self.src, st)
        dst = expr_to_z3(self.dst, st)
        if getattr(self, 'jmp32', False):
            width = 32
            dst = _resize(dst, 32)
            if src is not None:
                src = _resize(src, 32)
        else:
            width = max(dst.size(), src.size() if src is not None else 0)
            if self.code in Condition._SIGNED:
                width = max(width, 64)
        if src is not None and src.size() < width:
            src = Concat(BitVecVal(0, width - src.size()), src)
        if dst.size() < width:
            dst = Concat(BitVecVal(0, width - dst.size()), dst)
        if self.code == JEQ:  return dst == src
        if self.code == JNE:  return dst != src
        if self.code == JGT:  return UGT(dst, src)
        if self.code == JGE:  return UGE(dst, src)
        if self.code == JLT:  return ULT(dst, src)
        if self.code == JLE:  return ULE(dst, src)
        if self.code == JSGT: return dst > src
        if self.code == JSGE: return dst >= src
        if self.code == JSLT: return dst < src
        if self.code == JSLE: return dst <= src
        if self.code == JSET: return (dst & src) != 0
        raise Exception("Unknown branch code")


class adjust_head_check(Condition):
    def __init__(self, result: bool, idx: int = -1):
        self.result = result
        self.idx    = idx

    def __str__(self):
        return "adjust-success" if self.result else "adjust-failed"

    def to_z3(self, st):
        if self.idx < 0:
            return self.result
        ok = Bool(f'adjust{self.idx}_ok')
        return ok if self.result else Not(ok)


class contain_map_value(Condition):
    def __init__(self, map_id, map_key, map_key_id, result: bool):
        self.map_id     = map_id
        self.map_key    = map_key
        self.map_key_id = map_key_id
        self.result     = result

    def __str__(self):
        return f"{'!' if not self.result else ''}map{self.map_id}.contain(key{self.map_key_id})"

    def to_z3(self, st):
        if self.map_id is None or self.map_id < 0 or self.map_key is None:
            return BoolVal(self.result)
        if _is_array_map(st, self.map_id) or _is_prog_map(st, self.map_id):
            key       = _map_key_z3(st, self.map_id, self.map_key)
            max_entry = BitVecVal(_map_info(st, self.map_id)['max_entries'], key.size())
            in_bounds = ULT(key, max_entry)
            return in_bounds if self.result else Not(in_bounds)
        key = _map_key_z3(st, self.map_id, self.map_key)
        if st.read_present is not None:
            present = st.read_present(self.map_id, key, st.at_block,
                                      self.map_key_id)
        else:
            present = Select(st.map[self.map_id][0], key)
        return present == self.result


class tail_call_taken(Condition):
    def __init__(self, map_id, index, slot, target, idx: int = -1,
                 map_name: str = None):
        self.map_id   = map_id
        self.index    = index
        self.slot     = slot
        self.target   = target
        self.idx      = idx
        self.map_name = map_name

    def __str__(self):
        where = self.map_name or f'map{self.map_id}'
        at    = '?' if self.slot is None else self.slot
        return f"tail_call({where}[{at}] -> {self.target})"

    def to_z3(self, st):
        if self.slot is None or self.index is None:
            return Bool(f'tail{self.idx}_ok')
        key = expr_to_z3(self.index, st)
        return key == BitVecVal(self.slot, key.size())


class Action:
    block   = -1
    idx     = -1
    region  = None
    off     = 0
    var_off = None
    size    = 0
    map_id  = None
    map_key = None
    map_key_id = None

    presence = None

    def to_z3(self, st: Z3State):
        raise NotImplementedError


class Return(Action):
    def __init__(self, ret_code):
        self.ret_code = ret_code

    def __str__(self):
        return f"return {self.ret_code}"

    def to_z3(self, st):
        expr_z3 = expr_to_z3(self.ret_code, st)
        if expr_z3.size() < 64:
            expr_z3 = Concat(BitVecVal(0, 64 - expr_z3.size()), expr_z3)
        return Z3State(r0=expr_z3, st=st)


@dataclass
class PktWrite(Action):
    region = PKT

    id: int = -2
    off: int = -1
    var_off: Expr = None
    size: int = -1
    value: Expr = None

    def __str__(self):
        a = f"{self.var_off} + {hex(self.off)}" if self.var_off is not None else hex(self.off)
        rng = a if self.size == 1 else f"{a}:+{self.size}"
        return f"pkt[{rng}] <= {self.value}"

    def to_z3(self, st):
        dom  = st.pkt.domain().size()
        base = BitVecVal(self.off, dom)
        if self.var_off is not None:
            base = _resize(expr_to_z3(self.var_off, st), dom) + base
        val = _resize(expr_to_z3(self.value, st), self.size * 8)
        pkt = st.pkt
        for i in range(self.size):
            pkt = Store(pkt, base + BitVecVal(i, dom),
                        Extract((i + 1) * 8 - 1, i * 8, val))
        return Z3State(pkt=pkt, st=st)


@dataclass
class MapWrite(Action):
    region = MAP

    map_id: int = -1
    map_key: ByteSeq = None
    off: int = -1
    size: int = -1
    value: Expr = None
    var_off: Expr = None

    def __str__(self):
        rng = f"{self.off}:{self.off+self.size}" if self.size != 1 else str(self.off)
        at = f"{self.var_off} + {rng}" if self.var_off is not None else rng
        return f"{self.idx}: map{self.map_id}[{self.map_key}][{at}] <= {self.value}"

    def to_z3(self, st):
        if self.map_id is None or self.map_id < 0:
            return st
        key = _map_key_z3(st, self.map_id, self.map_key)
        cur = Select(st.map[self.map_id][1], key)
        val = expr_to_z3(self.value, st)
        if self.var_off is not None:
            base = _resize(expr_to_z3(self.var_off, st), cur.size()) + BitVecVal(self.off, cur.size())
            new_val = _splice_bytes_var(cur, base, self.size, val)
        else:
            new_val = _splice_bytes(cur, self.off, self.size, val)
        return _map_store(st, self.map_id, key, new_val, mark_present=False)


@dataclass
class MapAtomicAdd(Action):
    region = MAP

    map_id: int = -1
    map_key: ByteSeq = None
    off: int = -1
    size: int = -1
    value: Expr = None
    var_off: Expr = None
    old: Expr = None

    def __str__(self):
        at = f"{self.var_off} + {self.off}" if self.var_off is not None else str(self.off)
        return f"{self.idx}: map{self.map_id}[{self.map_key}][{at}] += {self.value}"

    def to_z3(self, st):
        if self.map_id is None or self.map_id < 0:
            return st
        key = _map_key_z3(st, self.map_id, self.map_key)
        cur = Select(st.map[self.map_id][1], key)
        if self.var_off is not None:
            base    = _resize(expr_to_z3(self.var_off, st), cur.size()) + BitVecVal(self.off, cur.size())
            field   = _extract_bytes_var(cur, base, self.size)
            addend  = _resize(expr_to_z3(self.value, st), field.size())
            new_val = _splice_bytes_var(cur, base, self.size, field + addend)
        else:
            lo, hi  = self.off * 8, min((self.off + self.size) * 8, cur.size())
            field   = Extract(hi - 1, lo, cur)
            addend  = _resize(expr_to_z3(self.value, st), field.size())
            new_val = _splice_bytes(cur, self.off, self.size, field + addend)
        return _map_store(st, self.map_id, key, new_val, mark_present=False)


class MapLookup(Action):
    imm = 1
    ret = 'map_ptr'

    def __init__(self, map_id: int, map_key, map_key_id: int):
        self.map_id     = map_id
        self.map_key    = map_key
        self.map_key_id = map_key_id

    def __str__(self):
        return f"map{self.map_id}.lookup(key{self.map_key_id})"

    def to_z3(self, st):
        return st


BPF_ANY, BPF_NOEXIST, BPF_EXIST = 0, 1, 2


def update_applies(update, present):
    if update.flags is None:
        return Bool(f'update{update.idx}_applies')
    mode = update.flags & 3
    if mode == BPF_ANY:
        return True
    if mode == BPF_NOEXIST:
        return _not(present)
    if mode == BPF_EXIST:
        return present
    return False


@dataclass
class MapUpdate(Action):
    region = MAP
    presence = True

    map_id: int = -1
    map_key: ByteSeq = None
    value: ByteSeq = None
    flags: int = 0
    off: int = 0
    size: int = -1

    def __str__(self):
        return f"{self.idx}: map{self.map_id}[{self.map_key}] <= {self.value}"

    def to_z3(self, st):
        if self.map_id is None or self.map_id < 0:
            return st
        key = _map_key_z3(st, self.map_id, self.map_key)
        val = _resize(expr_to_z3(self.value, st),
                      st.map[self.map_id][1].range().size())
        info = _map_info(st, self.map_id)
        if info is not None and (_is_array_map(st, self.map_id)
                                 or _is_prog_map(st, self.map_id)):
            present = ULT(key, BitVecVal(info['max_entries'], key.size()))
        else:
            present = Select(st.map[self.map_id][0], key)
        ok = update_applies(self, present)
        if ok is False:
            return st
        if ok is True:
            return _map_store(st, self.map_id, key, val, mark_present=True)
        new_map = [list(m) for m in st.map]
        new_map[self.map_id][1] = Store(st.map[self.map_id][1], key,
                                        If(ok, val, Select(st.map[self.map_id][1], key)))
        if _is_hash_map(st, self.map_id):
            new_map[self.map_id][0] = Store(st.map[self.map_id][0], key, Or(ok, present))
        return Z3State(map=new_map, st=st)

class MapDelete(Action):
    presence = False

    def __init__(self, map_id: int, map_key):
        self.map_id  = map_id
        self.map_key = map_key

    def __str__(self):
        return f"map{self.map_id}.delete({self.map_key})"

    def to_z3(self, st):
        if self.map_id is None or self.map_id < 0:
            return st
        if not _is_hash_map(st, self.map_id):
            return st
        key     = _map_key_z3(st, self.map_id, self.map_key)
        new_map = [list(m) for m in st.map]
        new_map[self.map_id][0] = Store(st.map[self.map_id][0], key, BoolVal(False))
        return Z3State(map=new_map, st=st)


@dataclass
class BssWrite(Action):
    region = BSS

    bss_key: str = None
    off: int = -1
    size: int = -1
    value: Expr = None
    var_off: Expr = None

    def __str__(self):
        at = (f"[{self.off}]" if self.var_off is None
              else f"[{self.var_off} + {self.off}]")
        return f"{self.idx}: {self.bss_key}{at} <= {self.value}"

    def to_z3(self, st):
        if self.bss_key is None:
            return st
        arr  = _bss_of(st, self.bss_key)
        base = BitVecVal(self.off, BSS_ADDR_BITS)
        if self.var_off is not None:
            base = _resize(expr_to_z3(self.var_off, st), BSS_ADDR_BITS) + base
        val = _resize(expr_to_z3(self.value, st), max(self.size, 1) * 8)
        for i in range(max(self.size, 1)):
            arr = Store(arr, base + BitVecVal(i, BSS_ADDR_BITS),
                        Extract((i + 1) * 8 - 1, i * 8, val))
        bss = dict(getattr(st, 'bss', None) or {})
        bss[self.bss_key] = arr
        return Z3State(bss=bss, st=st)


@dataclass
class BssAtomicAdd(Action):
    region = BSS

    bss_key: str = None
    off: int = -1
    size: int = -1
    value: Expr = None
    var_off: Expr = None
    old: Expr = None

    def __str__(self):
        at = (f"[{self.off}]" if self.var_off is None
              else f"[{self.var_off} + {self.off}]")
        return f"{self.idx}: {self.bss_key}{at} += {self.value}"

    def to_z3(self, st):
        if self.bss_key is None:
            return st
        old = bss_val(bss_key=self.bss_key, off=self.off,
                      var_off=self.var_off, size=max(self.size, 1))
        return BssWrite(self.bss_key, self.off, self.size,
                        ALUbinary(op=ADD, dst=old, src=self.value,
                                  size=max(self.size, 1)),
                        var_off=self.var_off).to_z3(st)


class AdjustHead(Action):
    imm = 44
    ret = 'scalar'
    ret_size = 8

    def __init__(self, delta: int, retval=None):
        self.delta  = delta
        self.retval = retval

    def __str__(self):
        return f"adjust_head({self.delta})"

    @property
    def len_delta(self) -> int:
        return self.delta

    def to_z3(self, st):
        shifted = st.pkt_len - self.len_delta
        if self.idx < 0:
            return Z3State(pkt_len=shifted, st=st)
        return Z3State(pkt_len=If(Bool(f'adjust{self.idx}_ok'), shifted, st.pkt_len),
                       st=st)


class AdjustTail(AdjustHead):
    imm = 65

    @property
    def len_delta(self) -> int:
        return -self.delta

    def __str__(self):
        return f"adjust_tail({self.delta})"


class AdjustMeta(Action):
    imm = 54
    ret = 'scalar'
    ret_size = 8

    def __init__(self, delta: int, retval=None):
        self.delta  = delta
        self.retval = retval

    def __str__(self):
        return f"adjust_meta({self.delta})"

    def to_z3(self, st):
        return st


class XdpBuffLen(Action):
    imm = 188
    ret = 'scalar'
    ret_size = 8

    def __init__(self, retval=None):
        self.retval = retval

    def __str__(self):
        return "xdp_get_buff_len()"

    def to_z3(self, st):
        return st


@dataclass
class CtxWrite(Action):
    region = CTX
    off    = 16
    size   = 4

    value: Expr = None

    def __str__(self):
        return f"{self.idx}: rx_queue_index <= {self.value}"

    def to_z3(self, st):
        expr_z3 = expr_to_z3(self.value, st)
        if expr_z3.size() < 64:
            expr_z3 = Concat(BitVecVal(0, 64 - expr_z3.size()), expr_z3)
        return Z3State(rx_index=expr_z3, st=st)


class TailCall(Action):
    imm = 12
    ret = 'transfer'

    def __init__(self, map_id, index, slot, target, map_name=None):
        self.map_id   = map_id
        self.map_key  = index
        self.index    = index
        self.slot     = slot
        self.target   = target
        self.map_name = map_name

    def __str__(self):
        where = self.map_name or f'map{self.map_id}'
        at    = '?' if self.slot is None else self.slot
        return f"{self.idx}: bpf_tail_call({where}[{at}]) -> {self.target}"

    def to_z3(self, st):
        return st


class perf_event_output(Action):
    def __str__(self):
        return "perf_event_output()"

    def to_z3(self, st):
        return st


class Goto(Action):
    def __init__(self, table_no: int):
        self.table_no = table_no

    def __str__(self):
        return f"goto T{self.table_no}"

    def to_z3(self, st):
        return self.table_no


def _and(a, b):
    if a is True:  return b
    if b is True:  return a
    if a is False or b is False: return False
    return And(a, b)


def _not(a):
    if a is True:  return False
    if a is False: return True
    return Not(a)


def _or_all(terms):
    terms = [t for t in terms if t is not False]
    if not terms:                     return False
    if any(t is True for t in terms): return True
    if len(terms) == 1:               return terms[0]
    return Or(terms)


def _make_init_state(maps, pkt0=None, map0=None, rx_index0=None,
                     ingress=None, egress=None, pkt_len_val=None) -> Z3State:
    pkt0      = pkt0      if pkt0      is not None else Array('pkt0', BitVecSort(PKT_ADDR_BITS), BitVecSort(8))
    rx_index0 = rx_index0 if rx_index0 is not None else BitVec('rx_queue_index0', 64)
    ingress   = ingress   if ingress   is not None else BitVec('ingress_ifindex',  64)
    egress    = egress    if egress    is not None else BitVec('egress_ifindex',   64)
    pkt_len_v = pkt_len_val if pkt_len_val is not None else BitVec('pkt_len', 64)
    if map0 is None:
        map0 = []
        for m in maps:
            Key = BitVecSort(max(m['key_size'], 1) * 8)
            Val = BitVecSort(max(m['value_size'], 1) * 8)
            map0.append([
                Array(f"present{m['id']}", Key, BoolSort()),
                Array(f"value{m['id']}",   Key, Val),
            ])
    return Z3State(
        pkt      = pkt0,
        map      = map0,
        r0       = BitVec('r0', 64),
        rx_index = rx_index0,
        ingress  = ingress,
        egress   = egress,
        pkt_len  = pkt_len_v,
    )
