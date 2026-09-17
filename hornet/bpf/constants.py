OPC_CLASS_MASK = 0x07
OPC_S_MASK     = 0x08
OPC_CODE_MASK  = 0xF0
OPC_SZ_MASK    = 0x18
OPC_MODE_MASK  = 0xE0

LD    = 0x0
LDX   = 0x1
ST    = 0x2
STX   = 0x3
ALU   = 0x4
JMP   = 0x5
JMP32 = 0x6
ALU64 = 0x7

S_IMM = 0x0
S_REG = 0x1

ADD  = 0x0
SUB  = 0x1
MUL  = 0x2
DIV  = 0x3
OR   = 0x4
AND  = 0x5
LSH  = 0x6
RSH  = 0x7
NEG  = 0x8
MOD  = 0x9
XOR  = 0xa
MOV  = 0xb
ARSH = 0xc
END  = 0xd

JA   = 0x0
JEQ  = 0x1
JGT  = 0x2
JGE  = 0x3
JSET = 0x4
JNE  = 0x5
JSGT = 0x6
JSGE = 0x7
CALL = 0x8
EXIT = 0x9
JLT  = 0xa
JLE  = 0xb
JSLT = 0xc
JSLE = 0xd

HELPER_TAIL_CALL = 12

IMM    = 0x0
ABS    = 0x1
IND    = 0x2
MEM    = 0x3
MEMSX  = 0x4
ATOMIC = 0x6

sz_map = {
    0: 4,
    1: 2,
    2: 1,
    3: 8,
}

alu_op_to_str = {
    ADD:  'BPF_ADD',
    SUB:  'BPF_SUB',
    MUL:  'BPF_MUL',
    DIV:  'BPF_DIV',
    OR:   'BPF_OR',
    AND:  'BPF_AND',
    LSH:  'BPF_LSH',
    RSH:  'BPF_RSH',
    NEG:  'BPF_NEG',
    MOD:  'BPF_MOD',
    XOR:  'BPF_XOR',
    MOV:  'BPF_MOV',
    ARSH: 'BPF_ARSH',
    END:  'BPF_END',
}

jmp_op_to_str = {
    JA:   'BPF_JA',
    JEQ:  'BPF_JEQ',
    JGT:  'BPF_JGT',
    JGE:  'BPF_JGE',
    JSET: 'BPF_JSET',
    JNE:  'BPF_JNE',
    JSGT: 'BPF_JSGT',
    JSGE: 'BPF_JSGE',
    CALL: 'BPF_CALL',
    EXIT: 'BPF_EXIT',
    JLT:  'BPF_JLT',
    JLE:  'BPF_JLE',
    JSLT: 'BPF_JSLT',
    JSLE: 'BPF_JSLE',
}

branch_op_to_str = {
    JEQ:  '==',
    JGT:  '>',
    JGE:  '>=',
    JSET: '&',
    JNE:  '!=',
    JSGT: '>s',
    JSGE: '>=s',
    JLT:  '<',
    JLE:  '<=',
    JSLT: '<s',
    JSLE: '<=s',
}

op_map = {
    ADD:  '+',
    SUB:  '-',
    MUL:  '*',
    DIV:  '/',
    OR:   '|',
    AND:  '&',
    LSH:  '<<',
    RSH:  '>>',
    NEG:  'NEG',
    MOD:  '%',
    XOR:  '^',
    ARSH: '>>s',
}

mode_to_str = {
    IMM:    'BPF_IMM',
    ABS:    'BPF_ABS',
    IND:    'BPF_IND',
    MEM:    'BPF_MEM',
    MEMSX:  'BPF_MEMSX',
    ATOMIC: 'BPF_ATOMIC',
}

sz_to_str = {
    0: 'W',
    1: 'H',
    2: 'B',
    3: 'DW',
}

def swap_jmp_code(code: int) -> int:
    _swap = {
        JEQ:  JNE,
        JNE:  JEQ,
        JGT:  JLE,
        JLE:  JGT,
        JGE:  JLT,
        JLT:  JGE,
        JSGT: JSLE,
        JSLE: JSGT,
        JSGE: JSLT,
        JSLT: JSGE,
    }
    return _swap.get(code, -1)


def arith(op: int, dst: int, src: int, bits: int = 64,
          signed: bool = False) -> int:
    mask = (1 << bits) - 1
    if op in (LSH, RSH, ARSH):
        amt, u = src & (bits - 1), dst & mask
        if op == LSH:
            return (u << amt) & mask
        if op == RSH:
            return u >> amt
        sval = u - (1 << bits) if u >> (bits - 1) else u
        return (sval >> amt) & mask
    if op in (DIV, MOD):
        a, b = dst & mask, src & mask
        if not signed:
            if op == DIV:
                return a // b if b else 0
            return a % b if b else a
        sa = a - (1 << bits) if a >> (bits - 1) else a
        sb = b - (1 << bits) if b >> (bits - 1) else b
        if sb == 0:
            return 0 if op == DIV else a
        mag = abs(sa) // abs(sb) if op == DIV else abs(sa) % abs(sb)
        neg = (sa < 0) != (sb < 0) if op == DIV else sa < 0
        return (-mag if neg else mag) & mask
    if bits == 32:
        return arith(op, dst & mask, src & mask) & mask
    if op == ADD:  return dst + src
    if op == SUB:  return dst - src
    if op == MUL:  return dst * src
    if op == OR:   return dst | src
    if op == AND:  return dst & src
    if op == NEG:  return -dst
    if op == XOR:  return dst ^ src
    return 0

PTR_TO_CTX = 0x00
PTR_TO_PKT = 0x01
PTR_TO_PKT_END = 0x02
PTR_TO_PKT_META = 0x03
PTR_TO_STK = 0x05
PTR_TO_MAP = 0x06
PTR_TO_MAP_VALUE = 0x07
PTR_TO_BSS = 0x08
PTR_TO_RODATA = 0x09
PTR_TO_DATA = 0x0a

BPF_MAP_TYPE_PROG_ARRAY = 3

MAP_TYPE_NAMES = {
    0:  'UNSPEC',              1:  'HASH',               2:  'ARRAY',
    3:  'PROG_ARRAY',          4:  'PERF_EVENT_ARRAY',   5:  'PERCPU_HASH',
    6:  'PERCPU_ARRAY',        7:  'STACK_TRACE',        8:  'CGROUP_ARRAY',
    9:  'LRU_HASH',            10: 'LRU_PERCPU_HASH',    11: 'LPM_TRIE',
    12: 'ARRAY_OF_MAPS',       13: 'HASH_OF_MAPS',       14: 'DEVMAP',
    15: 'SOCKMAP',             16: 'CPUMAP',             17: 'XSKMAP',
    18: 'SOCKHASH',            19: 'CGROUP_STORAGE',     20: 'REUSEPORT_SOCKARRAY',
    21: 'PERCPU_CGROUP_STORAGE', 22: 'QUEUE',            23: 'STACK',
    24: 'SK_STORAGE',          25: 'DEVMAP_HASH',        26: 'STRUCT_OPS',
    27: 'RINGBUF',             28: 'INODE_STORAGE',      29: 'TASK_STORAGE',
    30: 'BLOOM_FILTER',        31: 'USER_RINGBUF',       32: 'CGRP_STORAGE',
    33: 'ARENA',
}


def map_type_name(type_num: int) -> str:
    return MAP_TYPE_NAMES.get(type_num, f'type={type_num}')
