from __future__ import annotations
import copy

from bpf.constants import *
from bpf.instr import Instr
from track.block import (Block, PtrFacts, PktFacts, AdjustFacts, NO_FACT_ID,
                         null_fact_id)
from bpf.cfg import get_next_block_no
from track.expr import (
    Scalar, num, imm64, VAR_OFF_REGIONS,
    PTR,
    func_retval, pkt_len, pkt_val, map_val, bss_val,
    ingress_ifindex, rx_queue_index, egress_ifindex,
    ALUunary, ALUbinary, expr_alu, trunc32, sext,
)
from track.dce import drop_dead_phis
from track.encode import (
    pkt_size_check, BPF_MAP_TYPE_PROG_ARRAY, EINVAL,
    Condition, adjust_head_check, contain_map_value, tail_call_taken,
    AdjustHead, AdjustTail, AdjustMeta, XdpBuffLen, MapLookup, MapUpdate,
    perf_event_output, TailCall,
    PktWrite, MapWrite, BssWrite, CtxWrite, MapAtomicAdd, BssAtomicAdd
)
from bpf.link import region_of


def _is_ptr(x, ptr_type: int) -> bool:
    return isinstance(x, PTR) and x.ptr_type == ptr_type


def _adjust_ret_in(v):
    if isinstance(v, func_retval):
        return v if v.func in (44, 54, 65) else None
    if type(v) is ALUbinary:
        if isinstance(v.src, num):
            return _adjust_ret_in(v.dst)
        if isinstance(v.dst, num):
            return _adjust_ret_in(v.src)
        return None
    if type(v) is ALUunary and v.op == MOV:
        return _adjust_ret_in(v.dst)
    return None


def _eval_at(v, rv, ret: int):
    mask = (1 << 64) - 1
    if isinstance(v, func_retval):
        return ret & mask if v == rv else None
    if isinstance(v, num):
        return v.num & mask
    if type(v) is ALUbinary:
        a, b = _eval_at(v.dst, rv, ret), _eval_at(v.src, rv, ret)
        if a is None or b is None:
            return None
        return arith(v.op, a, b, bits=8 * v.size, signed=v.offset == 1) & mask
    if type(v) is ALUunary and v.op == MOV:
        a = _eval_at(v.dst, rv, ret)
        if a is None:
            return None
        low = a & ((1 << v.imm) - 1)
        low = low - (1 << v.imm) if low >> (v.imm - 1) else low
        return low & ((1 << (8 * v.size)) - 1)
    return None


def _jmp_taken(code: int, a: int, b: int, jmp32: bool) -> bool:
    bits = 32 if jmp32 else 64
    a, b = a & ((1 << bits) - 1), b & ((1 << bits) - 1)
    sa = a - (1 << bits) if a >> (bits - 1) else a
    sb = b - (1 << bits) if b >> (bits - 1) else b
    return {JEQ: a == b, JNE: a != b, JSET: (a & b) != 0,
            JGT: a > b, JGE: a >= b, JLT: a < b, JLE: a <= b,
            JSGT: sa > sb, JSGE: sa >= sb, JSLT: sa < sb, JSLE: sa <= sb}[code]


class Tracker:
    def __init__(self, blocks: list[Block], instrs: list[Instr], maps: list[dict],
                 progs: list = None, verbose: bool = False, rodata: dict = None):
        self.blocks  = blocks
        self.instrs  = instrs
        self.maps    = maps
        self.rodata_data = (rodata or {}).get('data') or b''
        self.progs   = progs or []
        self.verbose = verbose

        self.brief   = False
        self.var_num = 0
        self.id_box  = [0]
        self.sources = []

    def _new_ptr_id(self) -> int:
        self.id_box[0] += 1
        return self.id_box[0]

    def track(self, brief: bool = False) -> tuple[int, list]:
        blocks = self.blocks

        self.brief   = brief
        self.var_num = 0
        self.id_box  = [len(self.instrs)]
        self.sources = []

        untraced = set(range(len(blocks)))

        self.track_block(0)
        untraced.discard(0)

        while untraced:
            target = get_next_block_no(blocks, untraced)
            self.track_block(target)
            untraced.discard(target)

        self.sources = [v for b in blocks for v in b.sources]

        if not brief and self.verbose:
            print("Output Program:")
            for block in blocks:
                if block.actions:
                    print(f"Block{block.num}  Actions: "
                        f"{'; '.join(str(a) for a in block.actions)}")
                if block.branch:
                    print(f"  if {block.cond} goto {block.succ_t}")
                    print(f"  else goto {block.succ_f}")
                elif block.jump:
                    print(f"  goto {block.succ_t}")
                elif block.exit:
                    print(f"  return {block.regs[0]}")
                else:
                    print(f"  goto {block.succ_f}")

        return self.var_num, self.sources

    def track_block(self, block_no: int) -> None:
        blocks = self.blocks
        instrs = self.instrs

        block = blocks[block_no]

        if self.verbose:
            label = "brief-tracking" if self.brief else "tracking"
            print(f"----- {label} Block{block_no} -----")

        block.actions   = []
        block.sources   = []
        block.cond      = None
        block.cond_f    = None
        block.cond_t    = None
        block.ptr_facts = {}
        block.pkt_ptr_facts = {}
        block.adjust_pending = None
        block.new_ptr_id = self._new_ptr_id

        if block_no == 0:
            block.init_state()
        elif block.prog_entry is not None:
            block.init_tail_entry(blocks)
        else:
            block.merge_predecessors(blocks)

        if self.verbose:
            print(f"Block{block_no}: [{', '.join(str(r) for r in block.regs)}]")

        for i in range(block.start, block.end + 1):
            block.idx = i
            instr = instrs[i]
            if instr.is_alu():
                self.track_alu(i, block)
            elif instr.is_load():
                self.track_load(i, block)
            elif instr.is_store():
                self.track_store(i, block)
            elif instr.is_call():
                self.track_call(i, block)
            elif instr.is_branch():
                self.track_branch(i, block)
            elif instr.is_jump():
                pass

    def track_alu(self, idx: int, block: Block) -> None:
        instr  = self.instrs[idx]
        code   = instr.opcode_code
        s      = instr.opcode_s
        imm    = instr.imm
        offset = instr.offset
        size   = 8 if instr.opcode_class == ALU64 else 4

        src_value = block.regs[instr.src_reg]
        if s == S_IMM:
            src_value = (imm64(imm) if instr.opcode_class == ALU64
                         else num(num=imm, size=4))
        dst_value = block.regs[instr.dst_reg]

        if code == MOV and offset != 0:
            dst_new = (Scalar(size=8, idx=idx) if self.brief
                       else sext(src_value, offset, size, idx))

        elif code == MOV:
            dst_new = src_value if size == 8 else trunc32(src_value, idx)

        elif isinstance(dst_value, PTR):
            t = dst_value.ptr_type
            if dst_value.checked_null is None:
                dst_new = dst_value
            elif code not in (ADD, SUB):
                raise Exception(f"track_alu: unallowed arithmetic {code} on {t} pointer")

            elif (t == PTR_TO_PKT and code == SUB and isinstance(src_value, PTR)
                  and src_value.ptr_type == PTR_TO_PKT):
                if self.brief or dst_value.base_id != src_value.base_id:
                    dst_new = Scalar(size=8, idx=idx)
                else:
                    dst_new = expr_alu(dst_value.total_offset(),
                                       src_value.total_offset(), SUB, 8,
                                       brief=self.brief, idx=idx)

            elif t == PTR_TO_PKT:
                assert not isinstance(src_value, PTR), (
                    f"track_alu: unallowed arithmetic between two pointers {instr}")
                if isinstance(src_value, num):
                    delta = src_value.num if code == ADD else -src_value.num
                    dst_new = PTR(PTR_TO_PKT, off=dst_value.off + delta,
                                  var_off=dst_value.var_off, id=dst_value.id,
                                  base_id=dst_value.base_id)
                else:
                    base = dst_value.var_off if dst_value.var_off is not None else num(num=0)
                    var_off = expr_alu(base, src_value, code, size=4,
                                       brief=self.brief, idx=idx)
                    pid = block.new_ptr_id()
                    dst_new = PTR(PTR_TO_PKT, off=dst_value.off, var_off=var_off,
                                  id=pid, base_id=dst_value.base_id)
                    block.pkt_ptr_facts[pid] = PktFacts(id=pid, base_id=dst_value.base_id,
                                    ptr=dst_new, min_len=None, max_len=None)

            elif (t == PTR_TO_PKT_END and isinstance(src_value, PTR)
                  and src_value.ptr_type == PTR_TO_PKT):
                assert code == SUB, f"track_alu: pkt_end can only be subtracted from {instr}"
                if self.brief:
                    dst_new = Scalar(size=4, idx=idx)
                elif dst_value.base_id != src_value.base_id:
                    dst_new = ALUbinary(op=SUB, dst=dst_value, src=src_value,
                                        size=4, idx=idx)
                else:
                    dst_new = expr_alu(pkt_len(size=4, base_id=dst_value.base_id),
                                       src_value.total_offset(), SUB, 4,
                                       brief=self.brief, idx=idx)

            else:
                dst_new = copy.copy(dst_value)
                if isinstance(src_value, num):
                    dst_new.off = (dst_value.off + src_value.num if code == ADD
                                   else dst_value.off - src_value.num)
                elif t in VAR_OFF_REGIONS:
                    base = (dst_value.var_off if dst_value.var_off is not None
                            else num(num=0))
                    dst_new.var_off = expr_alu(base, src_value, code, size=8,
                                               brief=self.brief, idx=idx)
                else:
                    raise Exception(
                        f"track_alu: variable offset on {t:#x} pointer {instr}")

        elif code in (NEG, END):
            if self.brief:
                dst_new = Scalar(size=8, idx=idx)
            elif code == NEG and isinstance(dst_value, num):
                dst_new = (num(num=arith(NEG, dst_value.num, 0), idx=idx)
                           if size == 8 else
                           num(num=arith(NEG, dst_value.num, 0, bits=32),
                               size=4, idx=idx))
            else:
                width = (size if code == NEG
                         else imm // 8 if imm in (16, 32, 64) else 8)
                dst_new = ALUunary(op=code, dst=dst_value, opcode_s=s, imm=imm,
                                   size=width,
                                   alu64=(instr.opcode_class == ALU64))

        else:
            dst_new = expr_alu(dst_value, src_value, code, size, self.brief, idx,
                               offset=offset if code in (DIV, MOD) else 0)
            if size == 4 and dst_new is dst_value:
                dst_new = trunc32(dst_new, idx)

        block.regs[instr.dst_reg] = dst_new
        if self.verbose:
            print(f"{idx}: r{instr.dst_reg}={dst_new}")

    def track_load(self, idx: int, block: Block) -> None:
        instr = self.instrs[idx]
        clss  = instr.opcode_class
        mode  = instr.opcode_mode
        size  = sz_map[instr.opcode_sz]

        dst_new = None

        if clss == LD:
            if mode != IMM:
                raise Exception(f"track_load: invalid BPF_LD mode {mode}")
            assert instr.wide_instr and instr.src_reg == 0
            if instr.relocated:
                if instr.reloc_region == 0:
                    dst_new = PTR(PTR_TO_MAP, id=NO_FACT_ID, map_id=instr.reloc_tag)
                elif instr.reloc_region == 1:
                    dst_new = PTR(PTR_TO_BSS, instr.bss_offset, id=NO_FACT_ID,
                                  bss_idx=instr.reloc_tag)
                elif instr.reloc_region == 2:
                    dst_new = PTR(PTR_TO_RODATA, 0, id=NO_FACT_ID,
                                  rodata_offset=instr.rodata_offset,
                                  rodata_data=self.rodata_data)
            else:
                hi  = (instr.next_imm >> 32) & 0xFFFFFFFF
                val = (hi << 32) | (instr.imm & 0xFFFFFFFF)
                dst_new = num(num=val, size=8)

        elif clss == LDX:
            if mode not in (MEM, MEMSX):
                raise Exception(f"track_load: invalid BPF_LDX mode {mode}")
            src_ptr = block.regs[instr.src_reg]
            if not isinstance(src_ptr, PTR):
                raise Exception(f"track_load: src_reg {instr.src_reg} is not a PTR")
            dst_new = load(idx, block, src_ptr, instr.offset, size, self.brief)
            if mode == MEMSX and size < 8:
                dst_new = sext(dst_new, size * 8, 8, idx)

        block.regs[instr.dst_reg] = dst_new

        if self.verbose:
            print(f"{idx}: r{instr.dst_reg}<={dst_new}")

    def track_store(self, idx: int, block: Block) -> None:
        instr = self.instrs[idx]

        clss  = instr.opcode_class
        mode  = instr.opcode_mode
        imm = instr.imm
        offset = instr.offset
        size  = sz_map[instr.opcode_sz]

        src_value = block.regs[instr.src_reg]
        dst_value = block.regs[instr.dst_reg]

        if clss == ST:
            src_value = imm64(instr.imm)

        if mode in (ABS, IND):
            raise Exception("track_store: legacy packet access not implemented")
        elif mode in (IMM, MEMSX):
            raise Exception(f"track_store: invalid BPF_STX mode {mode}")
        elif mode == MEM:
            if not isinstance(dst_value, PTR):
                raise Exception(f"track_store: dst_reg {instr.dst_reg} is not a PTR")
            if dst_value.checked_null is not False:
                raise Exception(
                    f"track_store: store through a pointer not proven "
                    f"non-null: {dst_value} (checked_null={dst_value.checked_null})")

            t = dst_value.ptr_type
            addr = dst_value.off + offset
            if t == PTR_TO_STK:
                block.stk_store(addr, size, src_value, verbose=self.verbose)
            elif t == PTR_TO_CTX:
                assert addr == 16, "track_store: only rx_queue_index is writable"
                assert size == 4, "track_store: rx_queue_index size should be 4 bytes"
                block.emit(CtxWrite(src_value))
            elif t == PTR_TO_MAP_VALUE:
                map_id = dst_value.map_id
                map_key = dst_value.map_key
                block.emit(MapWrite(map_id, map_key, addr, size, src_value,
                                    var_off=dst_value.var_off))
            elif t == PTR_TO_BSS:
                key = dst_value.bss_idx
                block.emit(BssWrite(key, addr, size, src_value,
                                    var_off=dst_value.var_off))
            elif t == PTR_TO_PKT:
                id = dst_value.id
                var_off = dst_value.var_off
                block.emit(PktWrite(id, addr, var_off, size, src_value))
            else:
                raise Exception(f"track_store: unallowed store to {t} pointer")

        elif mode == ATOMIC:
            assert clss == STX
            fetch     = imm & 1
            atomic_op = imm & 0xF0
            if _is_ptr(dst_value, PTR_TO_STK):
                self._atomic_stack(idx, block, instr, dst_value.off + offset,
                                   size, src_value, atomic_op, fetch)
                return
            assert isinstance(dst_value, PTR) and dst_value.ptr_type in (PTR_TO_MAP_VALUE, PTR_TO_BSS)
            old_value = load(idx, block, dst_value, instr.offset, size, self.brief)

            t = dst_value.ptr_type
            addr = dst_value.off + offset
            if atomic_op == 0x00:
                if t == PTR_TO_MAP_VALUE:
                    map_id  = dst_value.map_id
                    map_key = dst_value.map_key
                    block.emit(MapAtomicAdd(map_id, map_key, addr, size, src_value,
                                            var_off=dst_value.var_off, old=old_value))
                elif t == PTR_TO_BSS:
                    key = dst_value.bss_idx
                    block.emit(BssAtomicAdd(key, addr, size, src_value,
                                            var_off=dst_value.var_off, old=old_value))
                else:
                    raise Exception(f"track_store: unallowed atomic add to {t} pointer")

            elif atomic_op in (0x40, 0x50, 0xa0, 0xe0, 0xf0):
                raise Exception(f"track_store: atomic op {atomic_op:#x} not implemented")
            else:
                raise Exception(f"track_store: unidentified atomic op {atomic_op:#x}")
            if fetch:
                block.regs[instr.src_reg] = old_value
        else:
            raise Exception(f"track_store: invalid BPF_STX mode {mode}")

    def _atomic_stack(self, idx: int, block: Block, instr, addr: int, size: int,
                      src_value, atomic_op: int, fetch: int) -> None:
        old = block.stk_load(addr, size)
        width = 4 if size == 4 else 8
        ops = {0x00: ADD, 0x40: OR, 0x50: AND, 0xa0: XOR}
        if atomic_op in ops:
            new = expr_alu(old, src_value, ops[atomic_op], width, self.brief, idx)
            block.stk_store(addr, size, new, verbose=self.verbose)
            if fetch:
                block.regs[instr.src_reg] = old
        elif atomic_op == 0xe0 and fetch:
            block.stk_store(addr, size, src_value, verbose=self.verbose)
            block.regs[instr.src_reg] = old
        elif atomic_op == 0xf0 and fetch:
            raise Exception("track_store: atomic cmpxchg on the stack not implemented")
        else:
            raise Exception(f"track_store: unidentified atomic op {instr.imm:#x}")

    def track_branch(self, idx: int, block: Block) -> None:
        instr = self.instrs[idx]
        code  = instr.opcode_code

        src_value = block.regs[instr.src_reg]
        if instr.opcode_s == S_IMM:
            src_value = (imm64(instr.imm) if instr.opcode_class == JMP
                         else num(num=instr.imm & 0xFFFFFFFF, size=4))
        dst_value = block.regs[instr.dst_reg]

        swapped_code = swap_jmp_code(code)
        if swapped_code == -1 and code != JSET:
            raise Exception(f"track_branch: no negation for jump code {code:#x}")

        set_cond_0 = None
        set_cond_1 = None

        rv = _adjust_ret_in(dst_value) or _adjust_ret_in(src_value)
        if rv is not None:
            jmp32 = instr.opcode_class == JMP32
            ends = [(_eval_at(dst_value, rv, ret), _eval_at(src_value, rv, ret))
                    for ret in (0, -EINVAL)]
            if all(x is not None for pair in ends for x in pair):
                ok_taken, failed_taken = (_jmp_taken(code, a, b, jmp32)
                                          for a, b in ends)
                if ok_taken != failed_taken:
                    pending = block.adjust_pending
                    if pending is not None and pending[0] == rv.idx:
                        before = pending[1]
                        block.set_cond_t(AdjustFacts(
                            idx=rv.idx, base_id=rv.idx if ok_taken else before))
                        block.set_cond_f(AdjustFacts(
                            idx=rv.idx, base_id=before if ok_taken else rv.idx))
                    if not self.brief:
                        block.cond = adjust_head_check(result=ok_taken, idx=rv.idx)
                    if self.verbose:
                        print(f"{idx}: branch on bpf_xdp_adjust_head@{rv.idx} "
                              f"/ {'success' if ok_taken else 'failure'} "
                              f"goto Block{block.succ_t} else Block{block.succ_f}")
                    return

        if (code != JSET and type(dst_value) == num and dst_value.num == 0
                and isinstance(src_value, PTR) and src_value.checked_null is None):
            dst_value, src_value = src_value, dst_value
            code = swapped_code
            swapped_code = swap_jmp_code(code)

        if isinstance(dst_value, PTR) and dst_value.checked_null is None:
            assert type(src_value) == num and src_value.num == 0
            if code not in (JEQ, JNE):
                if self.verbose:
                    print(f"{idx}: ordering test on a helper result "
                          f"({dst_value}) -- both edges kept")
                return
            if code == JNE:
                set_cond_0, set_cond_1 = block.set_cond_f, block.set_cond_t
            elif code == JEQ:
                set_cond_0, set_cond_1 = block.set_cond_t, block.set_cond_f
            else:
                raise Exception("track_branch: unallowed comparison against function result")

            pid = null_fact_id(dst_value)
            set_cond_0(PtrFacts(base_id=pid, ptr=dst_value, checked_null=True))
            set_cond_1(PtrFacts(base_id=pid, ptr=dst_value, checked_null=False))

            if self.brief:
                if self.verbose:
                    print(f"{idx}: branch null-check on {dst_value} "
                          f"/ goto Block{block.succ_t} else Block{block.succ_f}")
                return

            t   = dst_value.ptr_type
            res = (code != JEQ)
            if dst_value.null_phi is not None:
                block.cond = Condition(code=code, dst=dst_value.null_phi,
                                       src=num(num=0, size=1))
            elif t == PTR_TO_MAP_VALUE:
                block.cond = contain_map_value(dst_value.map_id, dst_value.map_key,
                                               dst_value.map_key_id, res)

        elif self.brief:
            if self.verbose:
                print(f"{idx}: branch r{instr.dst_reg} r{instr.src_reg} "
                      f"/ goto Block{block.succ_t} else Block{block.succ_f}")
            return

        elif pkt_size_check(dst_value, src_value):
            pkt_value = dst_value
            if isinstance(src_value, PTR) and src_value.ptr_type == PTR_TO_PKT:
                pkt_value = src_value
                code = {JGT: JLT, JGE: JLE, JLT: JGT, JLE: JGE}[code]
                assert code != None

            pid      = pkt_value.id
            base_id  = pkt_value.base_id
            offset   = pkt_value.off
            if code in (JGT, JGE):
                max_len_t = offset
                min_len_f = offset + 1
                if code == JGT:
                    max_len_t = offset - 1
                    min_len_f = offset
                block.set_cond_t(PktFacts(id=pid, base_id=base_id, min_len=None, max_len=max_len_t))
                block.set_cond_f(PktFacts(id=pid, base_id=base_id, min_len=min_len_f, max_len=None))
                total_offset = pkt_value.total_offset()
                block.cond = Condition(code=code, dst=total_offset, src=pkt_len(base_id=base_id))

            elif code in (JLT, JLE):
                min_len_t = offset + 1
                max_len_f = offset
                if code == JLE:
                    min_len_t = offset
                    max_len_f = offset + 1
                block.set_cond_t(PktFacts(id=pid, base_id=base_id, min_len=min_len_t, max_len=None))
                block.set_cond_f(PktFacts(id=pid, base_id=base_id, min_len=None, max_len=max_len_f))
                total_offset = pkt_value.total_offset()
                block.cond = Condition(code=code, dst=total_offset, src=pkt_len(base_id=base_id))
            else:
                raise Exception("track_branch: unidentified PTR_TO_PKT comparison code")

        else:
            block.cond = Condition(code=code, dst=dst_value, src=src_value,
                                   jmp32=(instr.opcode_class == JMP32))

    def _tail_region(self, idx: int, block: Block):
        if not self.progs:
            raise Exception(
                f"track_call: bpf_tail_call at {idx} but no callee was given "
                "-- pass --tail OBJ:ENTRY@SLOT")
        here = region_of(self.progs, idx)
        if here is not None and not here.is_main:
            raise Exception(
                f"track_call: bpf_tail_call at {idx} is inside {here.name!r}, "
                "which is itself a tail-call target. Chained tail calls are "
                "not implemented.")
        target = self.blocks[block.succ_t].prog_entry if block.succ_t is not None else None
        if target is None:
            raise Exception(
                f"track_call: bpf_tail_call at {idx} has no callee edge")
        return target

    def track_call(self, idx: int, block: Block) -> None:
        instr = self.instrs[idx]
        maps  = self.maps
        if instr.src_reg != 0:
            block.regs[0] = Scalar(size=8, idx=idx)
            return
        imm = instr.imm
        verbose_str = ''

        if imm == 1:
            map_ptr = block.regs[1]
            key_ptr = block.regs[2]
            assert isinstance(map_ptr, PTR) and map_ptr.ptr_type == PTR_TO_MAP
            assert isinstance(key_ptr, PTR)
            map_id       = map_ptr.map_id
            map_key_size = maps[map_id]['key_size']
            map_key      = load(idx=idx, block=block,ptr=key_ptr, offset=0, size=map_key_size)

            block.regs[0] = PTR(PTR_TO_MAP_VALUE, base_id=idx, map_id=map_id,
                                map_key=map_key, map_key_id=idx,
                                checked_null=None)
            if not self.brief:
                block.emit(MapLookup(map_id=map_id, map_key=map_key, map_key_id=idx))
            if self.verbose:
                verbose_str = f"{idx}: bpf_map_lookup_elem(map{map_id}, key{idx})"
            block.ptr_facts[idx] = PtrFacts(base_id=idx, ptr=block.regs[0], checked_null=None)

        elif imm == 2:
            key_ptr   = block.regs[2]
            value_ptr = block.regs[3]
            if (not _is_ptr(block.regs[1], PTR_TO_MAP) or not isinstance(key_ptr, PTR)
                    or not isinstance(value_ptr, PTR)):
                pass
            else:
                map_id         = block.regs[1].map_id
                map_key_size   = maps[map_id]['key_size']
                map_value_size = maps[map_id]['value_size']
                map_key        = load(idx=idx, block=block, ptr=key_ptr, offset=0, size=map_key_size)
                map_value      = load(idx=idx, block=block, ptr=value_ptr, offset=0, size=map_value_size)
                flags          = (block.regs[4].num if type(block.regs[4]) == num
                                  else None)
                block.emit(MapUpdate(map_id, map_key, map_value, flags,
                                     size=map_value_size))
                if self.verbose:
                    verbose_str = f"{idx}: bpf_map_update_elem(map{map_id}, {map_key}, {map_value})"
            block.regs[0] = Scalar(size=8, idx=idx)

        elif imm == 3:
            key_ptr = block.regs[2]
            if not _is_ptr(block.regs[1], PTR_TO_MAP) or not isinstance(key_ptr, PTR):
                block.regs[0] = Scalar(size=8, idx=idx)
            else:
                map_id       = block.regs[1].map_id
                map_key_size = maps[map_id]['key_size']
                map_key      = load(idx=idx, block=block, ptr=key_ptr, offset=0, size=map_key_size)
                if not self.brief:
                    from track.encode import MapDelete
                    block.emit(MapDelete(map_id=map_id, map_key=map_key))
                block.regs[0] = Scalar(size=8, idx=idx)
                if self.verbose:
                    verbose_str = f"{idx}: bpf_map_delete_elem(map{map_id}, key{idx})"

        elif imm in (5, 7, 8, 14, 15, 42, 118, 125, 160, 208):
            block.regs[0] = func_retval(size=(4 if imm == 7 else 8),
                                        idx=idx, func=imm, block=block.num)
            if not self.brief:
                block.sources.append(block.regs[0])

        elif imm == 25:
            block.emit(perf_event_output())
            block.regs[0] = Scalar(size=8, idx=idx)

        elif imm == 28:
            block.regs[0] = (Scalar(size=4, idx=idx) if self.brief
                             else func_retval(size=4, idx=idx, func=imm, block=block.num))
            if not self.brief:
                block.sources.append(block.regs[0])
            if self.verbose:
                verbose_str = f"{idx}: bpf_csum_diff({idx})"

        elif imm == 44:
            ctx_ptr = block.regs[1]
            assert _is_ptr(ctx_ptr, PTR_TO_CTX) and ctx_ptr.off == 0
            assert type(block.regs[2]) == num
            adjust = block.regs[2].num & 0xFFFFFFFF
            if adjust >= 1 << 31:
                adjust -= 1 << 32
            block.regs[0] = func_retval(idx=idx, func=imm, block=block.num)
            if not self.brief:
                block.emit(AdjustHead(adjust, retval=block.regs[0]))
            block.adjust_pending = (idx, ctx_ptr.base_id)
            block.set_ctx_view(None)
            if self.verbose:
                verbose_str = f"{idx}: bpf_xdp_adjust_head({adjust})"

        elif imm in (23, 51):
            map_ptr = block.regs[1] if imm == 51 else None
            flags   = block.regs[3] if imm == 51 else block.regs[2]
            map_id  = (map_ptr.map_id
                       if imm == 51 and _is_ptr(map_ptr, PTR_TO_MAP) else None)
            known = type(flags) == num and (imm == 51) == (map_id is not None)
            block.regs[0] = func_retval(
                idx=idx, func=imm, block=block.num,
                map_id=map_id, map_key=(block.regs[2] if imm == 51 else None),
                map_key_id=idx,
                fallback=(0 if not known else flags.num & 3 if imm == 51
                          else 4 if flags.num == 0 else 0),
                redirects=known)
            if not self.brief:
                block.sources.append(block.regs[0])
            if self.verbose:
                name = 'bpf_redirect_map' if imm == 51 else 'bpf_redirect'
                verbose_str = (f"{idx}: {name}(...) -> XDP_REDIRECT or "
                               + (f"{flags.num & 3}" if known else "unconstrained"))

        elif imm == 12:
            region = self._tail_region(idx, block)
            ctx_ptr, map_ptr, index = block.regs[1], block.regs[2], block.regs[3]
            if not _is_ptr(ctx_ptr, PTR_TO_CTX):
                raise Exception(
                    f"track_call: bpf_tail_call at {idx} was passed a "
                    f"non-ctx in r1 ({ctx_ptr})")
            if not _is_ptr(map_ptr, PTR_TO_MAP):
                raise Exception(
                    f"track_call: bpf_tail_call at {idx} was passed a "
                    f"non-map in r2 ({map_ptr})")
            map_id = map_ptr.map_id
            if maps[map_id]['type'] != BPF_MAP_TYPE_PROG_ARRAY:
                raise Exception(
                    f"track_call: bpf_tail_call at {idx} uses "
                    f"{maps[map_id]['name']!r}, which is not a PROG_ARRAY "
                    f"(type={maps[map_id]['type']})")
            if region.map_id != map_id:
                raise Exception(
                    f"track_call: bpf_tail_call at {idx} indexes "
                    f"{maps[map_id]['name']!r}, but {region.name!r} was loaded "
                    f"into {maps[region.map_id]['name']!r}")

            map_name = maps[map_id]['name']
            block.tail_ctx    = block.regs[1]
            block.tail_target = region
            block.cond = tail_call_taken(map_id=map_id, index=index,
                                         slot=region.slot, target=region.name,
                                         idx=idx, map_name=map_name)
            if not self.brief:
                block.emit(TailCall(map_id=map_id, index=index,
                                    slot=region.slot, target=region.name,
                                    map_name=map_name))
            block.regs[0] = Scalar(size=8, idx=idx)
            if self.verbose:
                verbose_str = f"{idx}: bpf_tail_call({map_name}[{region.slot}]) -> {region.name}"

        elif imm in (54, 65):
            ctx_ptr = block.regs[1]
            assert _is_ptr(ctx_ptr, PTR_TO_CTX) and ctx_ptr.off == 0
            assert type(block.regs[2]) == num
            adjust = block.regs[2].num & 0xFFFFFFFF
            if adjust >= 1 << 31:
                adjust -= 1 << 32
            block.regs[0] = func_retval(idx=idx, func=imm, block=block.num)
            if not self.brief:
                block.emit((AdjustTail if imm == 65 else AdjustMeta)(
                    adjust, retval=block.regs[0]))
            if self.verbose:
                name = 'bpf_xdp_adjust_tail' if imm == 65 else 'bpf_xdp_adjust_meta'
                verbose_str = f"{idx}: {name}({adjust})"

        elif imm == 188:
            ctx_ptr = block.regs[1]
            assert _is_ptr(ctx_ptr, PTR_TO_CTX) and ctx_ptr.off == 0
            r0 = pkt_len(size=8, base_id=block.pkt_base_id)
            block.regs[0] = r0
            if not self.brief:
                block.emit(XdpBuffLen(retval=r0))
            if self.verbose:
                verbose_str = f"{idx}: bpf_xdp_get_buff_len() -> {r0}"

        elif imm in (10, 11):
            raise Exception(
                f"track_call: helper imm={imm} "
                f"(bpf_l{'3' if imm == 10 else '4'}_csum_replace) takes a "
                f"__sk_buff: it is a TC helper and an XDP program cannot "
                f"reach it")

        else:
            raise Exception(f"track_call: unknown helper imm={imm}")

        for i in range(1, 6):
            block.regs[i] = None

        if self.verbose and verbose_str:
            print(verbose_str)

def load(idx: int, block: Block, ptr: PTR, offset: int, size: int, brief: bool = False):
    if ptr.checked_null is not False:
        raise Exception(
            f"load: dereference of a pointer not proven non-null: {ptr} "
            f"(checked_null={ptr.checked_null})")
    addr = ptr.off + offset
    t = ptr.ptr_type

    if t == PTR_TO_CTX:
        assert size == 4, "load: invalid ctx access size"
        region = {0: PTR_TO_PKT, 4: PTR_TO_PKT_END, 8: PTR_TO_PKT_META}.get(addr)
        if region is not None:
            return PTR(region, id=idx, base_id=ptr.base_id)
        if addr == 12: return Scalar(size=8, idx=-1) if brief else ingress_ifindex()
        if addr == 16: return Scalar(size=8, idx=-1) if brief else rx_queue_index()
        if addr == 20: return Scalar(size=8, idx=-1) if brief else egress_ifindex()
        else:
            raise Exception(f"load: unallowed ctx access at offset {addr}")

    elif t == PTR_TO_STK:
        return block.stk_load(addr, size)

    elif t == PTR_TO_PKT:
        value = pkt_val(block=block.num, idx=idx, off=addr, var_off=ptr.var_off, size=size)
        if not brief:
            block.sources.append(value)
        return value

    elif t == PTR_TO_MAP_VALUE:
        value = map_val(block=block.num, idx=idx, map_id=ptr.map_id, map_key=ptr.map_key,
                        map_key_id=ptr.map_key_id, off=addr, var_off=ptr.var_off,
                        size=size)
        if not brief:
            block.sources.append(value)
        return value

    elif t == PTR_TO_BSS:
        value = bss_val(block=block.num, idx=idx, bss_key=ptr.bss_idx,
                        off=addr, var_off=ptr.var_off, size=size)
        if not brief:
            block.sources.append(value)
        return value

    elif t == PTR_TO_RODATA:
        from track.expr import rodata_val
        data = ptr.rodata_data or b''
        base = (ptr.rodata_offset or 0) + addr
        if ptr.var_off is None:
            chunk = data[base:base + size] if base >= 0 else b''
            return num(num=int.from_bytes(chunk.ljust(size, b'\0'), 'little'),
                       size=size)
        return rodata_val(data=data, off=base, var_off=ptr.var_off, size=size)

    else:
        raise Exception(f"load: unallowed load from {t} pointer")
