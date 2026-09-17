from __future__ import annotations
from dataclasses import dataclass, field, replace

from bpf.constants import *


@dataclass(frozen=True)
class Expr:
    size: int = 8

@dataclass(frozen=True)
class Scalar(Expr):
    idx: int = -1
    def __str__(self):
        return f"scalar{self.idx}"

@dataclass(frozen=True)
class JoinValue(Scalar):
    size: int = 8
    block_idx: int = -1
    reg_num: int = -1
    values: list[Expr] = field(default_factory=list, compare=False, hash=False, repr=False)
    edges: list[tuple[int, str]] = field(default=(), compare=False, hash=False, repr=False)
    def __str__(self):
        return f"var{self.block_idx}_{self.reg_num}"

@dataclass(frozen=True)
class CtxScalar(Scalar):
    pass

@dataclass(frozen=True)
class ingress_ifindex(CtxScalar):
    size: int = 4
    def __str__(self):
        return "ingress_ifindex"

@dataclass(frozen=True)
class rx_queue_index(CtxScalar):
    size: int = 4
    def __str__(self):
        return "rx_queue_index"

@dataclass(frozen=True)
class egress_ifindex(CtxScalar):
    size: int = 4
    def __str__(self):
        return "egress_ifindex"

@dataclass(frozen=True)
class SymbolicData(Scalar):
    pass

@dataclass(frozen=True)
class pkt_len(SymbolicData):
    size: int = 4
    base_id: int = -1
    def __str__(self):
        named = self.base_id is not None and self.base_id >= 0
        name = f"pkt_len#{self.base_id}" if named else "pkt_len"
        return f"(u{self.size*8}) {name}()" if self.size != 8 else f"{name}()"

@dataclass(frozen=True)
class func_retval(SymbolicData):
    size: int = 8
    idx: int = -1
    func: int = -1
    block: int = -1

    map_id:     int = None
    map_key:    object = None
    map_key_id: int = None
    fallback:   int = 0
    redirects:  bool = False

    @property
    def imm(self): return self.func
    @property
    def ret(self): return 'scalar'
    @property
    def ret_size(self): return self.size
    def __str__(self):
        if self.func == 5:
            return f"(u{self.size*8}) ktime_get_ns{self.idx}()" if self.size != 8 else f"ktime_get_ns{self.idx}()"
        elif self.func == 7:
            return f"(u{self.size*8}) rand{self.idx}()" if self.size != 8 else f"rand{self.idx}()"
        elif self.func == 8:
            return f"(u{self.size*8}) processor_id{self.idx}()" if self.size != 8 else f"processor_id{self.idx}()"
        elif self.func == 28:
            return f"(u{self.size*8}) csum_diff{self.idx}()" if self.size != 8 else f"csum_diff{self.idx}()"
        elif self.func == 14:
            return f"(u{self.size*8}) pid_tgid{self.idx}()" if self.size != 8 else f"pid_tgid{self.idx}()"
        elif self.func == 15:
            return f"(u{self.size*8}) uid_gid{self.idx}()" if self.size != 8 else f"uid_gid{self.idx}()"
        elif self.func == 42:
            return f"(u{self.size*8}) numa_node{self.idx}()" if self.size != 8 else f"numa_node{self.idx}()"
        elif self.func == 118:
            return f"(u{self.size*8}) jiffies{self.idx}()" if self.size != 8 else f"jiffies{self.idx}()"
        elif self.func == 125:
            return f"(u{self.size*8}) ktime_boot{self.idx}()" if self.size != 8 else f"ktime_boot{self.idx}()"
        elif self.func == 160:
            return f"(u{self.size*8}) ktime_coarse{self.idx}()" if self.size != 8 else f"ktime_coarse{self.idx}()"
        elif self.func == 208:
            return f"(u{self.size*8}) ktime_tai{self.idx}()" if self.size != 8 else f"ktime_tai{self.idx}()"
        else:
            return f"(u{self.size*8}) func{self.idx}()" if self.size != 8 else f"func{self.idx}()"
    def __eq__(self, other):
        return (type(self) == type(other) and self.idx == other.idx
                and self.func == other.func)
    def __hash__(self):
        return hash((self.idx, self.func))

@dataclass(frozen=True)
class pkt_val(SymbolicData):
    block: int = -1
    idx: int = -1
    off: int = 0
    var_off: Expr = None
    size: int = 1

    def byte(self, i: int) -> 'pkt_val':
        return replace(self, off=self.off + i, size=1)

    def __str__(self):
        a = f"{self.var_off} + {hex(self.off)}" if self.var_off is not None else hex(self.off)
        return f"pkt[{a}]" if self.size == 1 else f"pkt[{a}:+{self.size}]"


@dataclass(frozen=True)
class map_val(SymbolicData):
    block: int = -1
    idx: int = -1
    map_id: int = -1
    map_key: Expr = None
    map_key_id: int = -1
    off: int = 0
    var_off: Expr = None
    size: int = 1

    def byte(self, i: int) -> 'map_val':
        return replace(self, off=self.off + i, size=1)

    def __str__(self):
        a = f"{self.var_off} + {hex(self.off)}" if self.var_off is not None else hex(self.off)
        rng = a if self.size == 1 else f"{a}:+{self.size}"
        return f"map{self.map_id}[key{self.map_key_id}][{rng}]"

VAR_OFF_REGIONS = frozenset({PTR_TO_PKT, PTR_TO_MAP_VALUE,
                             PTR_TO_BSS, PTR_TO_DATA, PTR_TO_RODATA})


@dataclass(frozen=True)
class bss_val(SymbolicData):
    block: int = -1
    idx: int = -1
    bss_key: str = None
    off: int = 0
    var_off: Expr = None
    size: int = 1

    def byte(self, i: int) -> 'bss_val':
        return replace(self, off=self.off + i, size=1)

    def __str__(self):
        a = (f"{self.var_off} + {hex(self.off)}" if self.var_off is not None
             else hex(self.off))
        rng = a if self.size == 1 else f"{a}:+{self.size}"
        return f"{self.bss_key}[{rng}]"


@dataclass(frozen=True)
class rodata_val(SymbolicData):
    data: bytes = b''
    off: int = 0
    var_off: Expr = None
    size: int = 1

    def __str__(self):
        a = (f"{self.var_off} + {hex(self.off)}" if self.var_off is not None
             else hex(self.off))
        rng = a if self.size == 1 else f"{a}:+{self.size}"
        return f"rodata[{rng}]"


@dataclass(frozen=True)
class lookup_hit(SymbolicData):
    map_id: int = None
    map_key: Expr = None
    map_key_id: int = None
    size: int = 1

    def __str__(self):
        return f"map{self.map_id}.contain(key{self.map_key_id})"


@dataclass(frozen=True)
class num(Expr):
    num: int = 0
    size: int = 8
    idx: int = -1
    def __str__(self):
        return hex(self.num)
    def __eq__(self, other):
        if isinstance(other, num):
            return other.num == self.num and other.idx == self.idx
        if type(other) == int:
            return other == self.num
        return False
    def __hash__(self):
        return hash(self.num)


def imm64(imm: int) -> num:
    return num(num=imm, size=4 if imm >= 0 else 8)

@dataclass(frozen=True)
class ByteSeq(Expr):
    chunks: tuple = ()
    size: int = 8
    off: int = 0
    def __init__(self, chunks: tuple, size: int, off: int = 0):
        object.__setattr__(self, "chunks", tuple(chunks))
        object.__setattr__(self, "size", size)
        object.__setattr__(self, "off", off)
    def __str__(self):
        body = "[" + ", ".join(str(c) for c in self.chunks) + "]"
        return f"{body}+{self.off}:{self.size}" if self.off else f"{body}:{self.size}"


@dataclass(frozen=True, eq=False)
class ALUunary(Scalar):
    op: int = 0
    dst: Expr = None
    opcode_s: int = None
    imm: int = 0
    size: int = 8
    alu64: bool = True

    def __hash__(self):
        h = self.__dict__.get('_h')
        if h is None:
            h = hash((ALUunary, self.op, self.size, self.imm, self.opcode_s,
                      self.alu64, hash(self.dst)))
            object.__setattr__(self, '_h', h)
        return h

    def __eq__(self, other):
        if self is other:
            return True
        if type(other) is not ALUunary or hash(other) != hash(self):
            return False
        return (self.op == other.op and self.size == other.size
                and self.imm == other.imm and self.opcode_s == other.opcode_s
                and self.alu64 == other.alu64 and self.dst == other.dst)

    def _body(self, emit) -> str:
        if self.op == NEG:
            return f"-({emit(self.dst)})"
        if self.op == MOV:
            u32 = '(u32) ' if self.size == 4 else ''
            return f"{u32}sext{self.imm}({emit(self.dst)})"
        if self.alu64:
            return f"bswap{self.imm}({emit(self.dst)})"
        return (f"le{self.imm}({emit(self.dst)})" if self.opcode_s == S_IMM
                else f"be{self.imm}({emit(self.dst)})")

    def __str__(self):
        return expr_to_str(self)


@dataclass(frozen=True, eq=False)
class ALUbinary(Scalar):
    op: int = 0
    dst: Expr = None
    src: Expr = None
    offset: int = 0
    size: int = 8
    idx: int = -1

    def __hash__(self):
        h = self.__dict__.get('_h')
        if h is None:
            h = hash((ALUbinary, self.op, self.size, self.offset,
                      hash(self.dst), hash(self.src)))
            object.__setattr__(self, '_h', h)
        return h

    def __eq__(self, other):
        if self is other:
            return True
        if type(other) is not ALUbinary or hash(other) != hash(self):
            return False
        return (self.op == other.op and self.size == other.size
                and self.offset == other.offset
                and self.dst == other.dst and self.src == other.src)

    def _body(self, emit) -> str:
        size_str = f"(u{self.size*8}) " if self.size != 8 else ''
        return f"{size_str}({emit(self.dst)} {op_map[self.op]} {emit(self.src)})"

    def __str__(self):
        return expr_to_str(self)


_ALU_NODES = (ALUunary, ALUbinary)


def _alu_children(n) -> tuple:
    return (n.dst,) if type(n) is ALUunary else (n.dst, n.src)


def expr_to_str(root) -> str:
    if type(root) not in _ALU_NODES:
        return str(root)

    ref = {}
    seen = {id(root)}
    stack = [root]
    while stack:
        n = stack.pop()
        for c in _alu_children(n):
            if type(c) in _ALU_NODES:
                ref[id(c)] = ref.get(id(c), 0) + 1
                if id(c) not in seen:
                    seen.add(id(c))
                    stack.append(c)
    shared = {nid for nid, cnt in ref.items() if cnt > 1}

    labels = {}
    defs = []

    def emit(n):
        if type(n) not in _ALU_NODES:
            return str(n)
        if id(n) not in shared:
            return n._body(emit)
        if id(n) not in labels:
            rendered = n._body(emit)
            labels[id(n)] = f"$t{len(defs)}"
            defs.append((labels[id(n)], rendered))
        return labels[id(n)]

    top = emit(root) if id(root) in shared else root._body(emit)
    if not defs:
        return top
    binds = "; ".join(f"{lbl} = {rendered}" for lbl, rendered in defs)
    return f"let {binds} in {top}"


class PTR:
    size: int = 4

    def __init__(self, ptr_type: int, off: int = 0, var_off: 'Expr | None' = None, *,
                 id: int = -1, base_id: int = -1, map_id: int = None,
                 map_key: 'Expr' = None, map_key_id: int = None,
                 bss_idx: int = None, rodata_offset: int = None,
                 rodata_data: bytes = None,
                 checked_null: 'bool | None' = False):
        if var_off is not None:
            assert ptr_type in VAR_OFF_REGIONS, (
                f"variable offset is not supported for ptr_type={ptr_type:#x}; "
                f"allowed: {sorted(VAR_OFF_REGIONS)}")
        if ptr_type in (PTR_TO_PKT_END, PTR_TO_MAP):
            assert off == 0, (
                f"ptr_type={ptr_type:#x} supports offset 0 only, got {off}")

        self.size = 4
        self.ptr_type = ptr_type

        self.off = off
        self.var_off = var_off

        self.id = id
        self.base_id = base_id

        self.map_id = map_id
        self.map_key = map_key
        self.map_key_id = map_key_id

        self.bss_idx = bss_idx
        self.rodata_offset = rodata_offset
        self.rodata_data = rodata_data

        self.checked_null = checked_null

        self.null_phi = None

    def total_offset(self) -> 'Expr':
        if self.var_off is None:
            return num(num=self.off)
        return expr_alu(self.var_off, num(num=self.off), ADD, 4)

    def __eq__(self, other):
        if not isinstance(other, PTR) or self.ptr_type != other.ptr_type:
            return False
        if self.ptr_type in (PTR_TO_PKT, PTR_TO_PKT_END, PTR_TO_PKT_META):
            return (self.off == other.off and self.var_off == other.var_off
                    and self.base_id == other.base_id)
        if self.ptr_type == PTR_TO_MAP_VALUE:
            return (self.off == other.off and self.var_off == other.var_off
                    and self.map_id == other.map_id
                    and self.map_key_id == other.map_key_id)
        return self.off == other.off and self.var_off == other.var_off

    def __hash__(self):
        return hash((self.ptr_type, self.off))

    def __str__(self):
        t = self.ptr_type
        addr = self.total_offset() if self.var_off is not None else self.off
        q = "?" if self.checked_null is None else ""
        if t == PTR_TO_CTX:               return f"(void *) ctx + {addr}{q}"
        if t == PTR_TO_PKT:               return f"(void *) pkt+{addr}{q}"
        if t == PTR_TO_PKT_END:           return "(void *) pkt_end"
        if t == PTR_TO_PKT_META:          return "(void *) pkt_meta"
        if t == PTR_TO_STK:               return f"(void *) stk-{-self.off}"
        if t == PTR_TO_MAP:               return f"(void *) map{self.map_id}"
        if t == PTR_TO_MAP_VALUE:         return f"(void *) map{self.map_id}[key{self.map_key_id}]+{addr}{q}"
        if t == PTR_TO_BSS:               return f"(void *) bss{self.bss_idx}+{addr}"
        if t == PTR_TO_RODATA:            return f"(void *) rodata+{self.rodata_offset}+{addr}"
        if t == PTR_TO_DATA:              return f"(void *) data+{addr}"
        return f"(void *) ptr{t:#x}+{addr}"


def expr_alu(dst_value, src_value, code, size, brief=False, idx=-1, offset=0):
    if isinstance(dst_value, num) and isinstance(src_value, num):
        signed = offset == 1 and code in (DIV, MOD)
        if size == 4:
            return num(num=arith(code, dst_value.num, src_value.num, bits=32,
                                 signed=signed),
                       size=4, idx=idx)
        return num(num=arith(code, dst_value.num, src_value.num,
                             signed=signed), idx=idx)

    if code in (ADD, SUB) and isinstance(src_value, num) and src_value.num == 0:
        return dst_value

    if brief:
        return Scalar(size=8, idx=idx)

    return ALUbinary(op=code, dst=dst_value, src=src_value, size=size, idx=idx,
                     offset=offset)


def trunc32(value, idx=-1):
    if value is None or isinstance(value, PTR):
        return value
    if isinstance(value, num):
        return num(num=value.num & 0xFFFFFFFF, size=4, idx=idx)
    if value.size <= 4:
        return value
    return ALUbinary(op=AND, dst=value, src=num(num=0xFFFFFFFF, size=4),
                     size=4, idx=idx)


def sext(value, bits, size=8, idx=-1):
    if value is None:
        return None
    if isinstance(value, PTR):
        raise Exception(f"sext: sign extension of a pointer {value}")
    if isinstance(value, num):
        v = value.num & ((1 << bits) - 1)
        v = v - (1 << bits) if v >> (bits - 1) else v
        if size == 4:
            return num(num=v & 0xFFFFFFFF, size=4, idx=idx)
        return num(num=v, size=8, idx=idx)
    return ALUunary(op=MOV, dst=value, imm=bits, size=size, alu64=(size == 8))
