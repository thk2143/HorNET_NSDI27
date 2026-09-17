from __future__ import annotations
import copy
from dataclasses import dataclass, field
from typing import Any, Optional

from bpf.constants import (
    PTR_TO_CTX, PTR_TO_PKT, PTR_TO_PKT_END, PTR_TO_PKT_META,
    PTR_TO_STK, PTR_TO_MAP_VALUE,
    OR, AND, LSH,
)
from track.expr import (
    Expr, num, ByteSeq, PTR, ALUbinary, JoinValue, lookup_hit
)


PKT_REGIONS = (PTR_TO_PKT, PTR_TO_PKT_END, PTR_TO_PKT_META)

NO_FACT_ID = -2


def null_fact_id(ptr: 'PTR') -> int:
    return ptr.id if ptr.id != -1 else ptr.base_id


def is_null_const(v) -> bool:
    return isinstance(v, num) and v.num == 0


def _fold_nullity(vals):
    first = vals[0]
    return first if all(v is first for v in vals) else None


def _with_nullity(ptr: 'PTR', nullity) -> 'PTR':
    if ptr.checked_null is nullity:
        return ptr
    out = copy.copy(ptr)
    out.checked_null = nullity
    return out


def _with_view(v, base_id):
    if not isinstance(v, PTR) or v.ptr_type != PTR_TO_CTX or v.base_id == base_id:
        return v
    out = copy.copy(v)
    out.base_id = base_id
    return out


def _nullity_value(v):
    if is_null_const(v):
        return num(num=0, size=1)
    if not isinstance(v, PTR):
        return None
    if v.checked_null is False:
        return num(num=1, size=1)
    if v.checked_null is True:
        return num(num=0, size=1)
    if v.null_phi is not None:
        return v.null_phi
    if (v.ptr_type == PTR_TO_MAP_VALUE and v.map_key is not None
            and v.map_key_id is not None and v.map_key_id == v.base_id):
        return lookup_hit(map_id=v.map_id, map_key=v.map_key,
                          map_key_id=v.map_key_id)
    return None


def _same(a, b) -> bool:
    if isinstance(a, JoinValue) or isinstance(b, JoinValue):
        return a is b
    return a == b


@dataclass
class PtrFacts:
    base_id: Optional[int] = None
    ptr: Optional[PTR] = None
    checked_null: Optional[bool] = None


@dataclass
class PktFacts:
    id: int = -1
    base_id: int = -1
    ptr: Optional[PTR] = None
    min_len: Any = None
    max_len: Any = None


@dataclass
class AdjustFacts:
    idx: int = -1
    base_id: Optional[int] = None


@dataclass
class Block:

    num:   int
    start: int
    end:   int

    preds:  list[int]       = field(default_factory=list)
    succ_f: Optional[int]   = None
    succ_t: Optional[int]   = None

    exit:   Optional[bool]  = None
    jump:   Optional[bool]  = None
    branch: Optional[bool]  = None

    prog_entry: Any = None
    tail_ctx:    Any = None
    tail_target: Any = None

    regs:     list[Any]     = field(default_factory=lambda: [None] * 11)
    stk:      list[Any]     = field(default_factory=list)
    actions:  list[Any]     = field(default_factory=list)
    sources: list[Any]      = field(default_factory=list)

    cond:  Any              = None

    cond_f: Any = None
    cond_t: Any = None

    ptr_facts: dict[int, PtrFacts] = field(default_factory=dict)
    pkt_ptr_facts: dict[int, PktFacts] = field(default_factory=dict)

    id_box: list = field(default_factory=lambda: [0])

    pkt_base_id: int = -1

    adjust_pending: Any = None

    idx: Optional[int] = None


    @property
    def kind(self) -> str:
        if self.branch: return 'branch'
        if self.jump:   return 'jump'
        if self.exit:   return 'exit'
        return 'fall'

    @property
    def ret_expr(self):
        return self.regs[0] if self.exit else None


    def set_cond_f(self, cond) -> None:
        self.cond_f = cond

    def set_cond_t(self, cond) -> None:
        self.cond_t = cond

    def emit(self, action) -> None:
        action.block = self.num
        action.idx   = self.idx
        self.actions.append(action)

    def new_ptr_id(self) -> int:
        return self.new_ptr_id_func()

    def set_ctx_view(self, base_id) -> None:
        self.regs = [_with_view(r, base_id) for r in self.regs]
        self.stk  = [_with_view(c, base_id) for c in self.stk]
        self.pkt_base_id = base_id


    def init_state(self) -> None:
        self.regs[1]   = PTR(PTR_TO_CTX, id=-1)
        self.regs[10]  = PTR(PTR_TO_STK, id=NO_FACT_ID)
        self.ptr_facts = dict()
        self.ptr_facts[NO_FACT_ID] = PtrFacts(base_id=NO_FACT_ID, checked_null=False)
        self.ptr_facts[-1] = PtrFacts(base_id=-1, checked_null=False)
        self.pkt_ptr_facts = {}
        self.pkt_ptr_facts[-1] = PktFacts(id=-1, base_id=-1, ptr=None,min_len=None, max_len=None)
        self.pkt_base_id = -1
        self.stk       = []

    def init_tail_entry(self, blocks: list[Block]) -> None:
        sites = [blocks[p] for p in self.preds if blocks[p].succ_t == self.num]
        ctxs  = {id(b.tail_ctx): b.tail_ctx for b in sites
                 if isinstance(b.tail_ctx, PTR)}
        bases = {c.base_id for c in ctxs.values()}
        if len(bases) > 1:
            raise Exception(
                f"init_tail_entry: block {self.num} is tail-called from sites "
                f"that disagree on the packet view (ctx base ids {sorted(bases)}). "
                "One of them adjusted the packet head and the other did not, "
                "and hornet models one view per program entry.")

        ctx = next(iter(ctxs.values()), None)

        self.regs = [None] * 11
        self.regs[1]  = ctx if ctx is not None else PTR(PTR_TO_CTX, id=-1)
        self.regs[10] = PTR(PTR_TO_STK, id=NO_FACT_ID)
        self.stk      = []

        base = self.regs[1].base_id
        self.ptr_facts = {NO_FACT_ID: PtrFacts(base_id=NO_FACT_ID,
                                               checked_null=False)}
        self.ptr_facts[base] = PtrFacts(base_id=base, ptr=self.regs[1],
                                        checked_null=False)
        self.pkt_ptr_facts = {base: self._entry_pkt_facts(sites, base)}
        self.pkt_base_id = base

    @staticmethod
    def _entry_pkt_facts(sites, base) -> PktFacts:
        facts = [b.pkt_ptr_facts.get(base) for b in sites]
        mins  = {None if f is None else f.min_len for f in facts}
        maxs  = {None if f is None else f.max_len for f in facts}
        return PktFacts(id=base, base_id=base, ptr=None,
                        min_len=mins.pop() if len(mins) == 1 else None,
                        max_len=maxs.pop() if len(maxs) == 1 else None)

    def _stamp_null_phi(self, ptr, pred_edges, entries, reg_num):
        if not isinstance(ptr, PTR) or ptr.checked_null is not None:
            return ptr
        vals = [_nullity_value(v) for v in entries]
        phi = None
        if all(v is not None for v in vals):
            if all(_same(v, vals[0]) for v in vals):
                phi = vals[0] if isinstance(vals[0], JoinValue) else None
            else:
                values, edges = [], []
                for (pred, edge), v in zip(pred_edges, vals):
                    k = next((i for i, u in enumerate(values) if _same(u, v)), None)
                    if k is None:
                        values.append(v)
                        edges.append([(pred, edge)])
                    else:
                        edges[k].append((pred, edge))
                phi = JoinValue(block_idx=self.num, reg_num=reg_num,
                                values=values, edges=edges)
                self.sources.append(phi)
        if phi is ptr.null_phi:
            return ptr
        out = copy.copy(ptr)
        out.null_phi = phi
        return out

    def merge_entry(self, pred_edges, entries, reg_num, pred_conds=None) -> Expr:
        resolved = []
        for k, v in enumerate(entries):
            c = pred_conds[k] if pred_conds else None
            if isinstance(c, AdjustFacts):
                v = _with_view(v, c.base_id)
            if isinstance(v, PTR) and v.checked_null is None:
                fid = null_fact_id(v)
                f = (c if isinstance(c, PtrFacts) and c.base_id == fid
                     else self.ptr_facts.get(fid))
                if f is not None and f.checked_null is False:
                    v = _with_nullity(v, False)
                elif f is not None and f.checked_null is True:
                    v = num(num=0, size=8, idx=-1)
            resolved.append(v)
        entries = resolved

        if None in entries:
            return None

        ptr_at = [k for k, r in enumerate(entries) if isinstance(r, PTR)]
        if ptr_at and len(ptr_at) != len(entries):
            if not all(is_null_const(entries[k]) for k in range(len(entries))
                       if k not in ptr_at):
                return None
            merged = self.merge_entry([pred_edges[k] for k in ptr_at],
                                      [entries[k] for k in ptr_at],
                                      reg_num, None)
            if not isinstance(merged, PTR):
                return None
            out = _with_nullity(merged, None)
            if merged.checked_null is not None:
                out.id = self.new_ptr_id()
                if out.ptr_type == PTR_TO_PKT:
                    self.pkt_ptr_facts[out.id] = PktFacts(
                        id=out.id, base_id=out.base_id, ptr=out,
                        min_len=None, max_len=None)
            return self._stamp_null_phi(out, pred_edges, entries, reg_num)

        first = entries[0]
        if isinstance(first, PTR):
            if any(not isinstance(r, PTR) or r.ptr_type != first.ptr_type
                    for r in entries):
                return None

            nullity = _fold_nullity([r.checked_null for r in entries])

            if first.ptr_type == PTR_TO_PKT:
                if any(r.base_id != first.base_id for r in entries):
                    return None

                if any(first is not r for r in entries):
                    tracked = []
                    values = []
                    edges = []
                    for (pred, edge), r in zip(pred_edges, entries):
                        if r not in tracked:
                            tracked.append(r)
                            values.append(r.total_offset())
                            edges.append([(pred, edge)])
                        else:
                            edges[tracked.index(r)].append((pred, edge))
                    var_off = JoinValue(block_idx=self.num, reg_num=reg_num,
                                        values=values, edges=edges)
                    self.sources.append(var_off)
                    new_id = self.new_ptr_id()
                    new_ptr = PTR(PTR_TO_PKT, off=0, var_off=var_off, id=new_id,
                                        base_id=first.base_id, checked_null=nullity)
                    self.pkt_ptr_facts[new_ptr.id] = PktFacts(id=new_ptr.id, base_id=new_ptr.base_id,
                                                            ptr=new_ptr,min_len=None, max_len=None)
                    return self._stamp_null_phi(new_ptr, pred_edges, entries, reg_num)
                return self._stamp_null_phi(_with_nullity(first, nullity), pred_edges, entries, reg_num)

            elif first.ptr_type == PTR_TO_MAP_VALUE:
                if any(r.map_id != first.map_id or r.off != first.off for r in entries):
                    return None
                if all(r.map_key_id == first.map_key_id for r in entries):
                    return self._stamp_null_phi(_with_nullity(first, nullity), pred_edges, entries, reg_num)
                tracked = []
                values = []
                edges = []
                for (pred, edge), r in zip(pred_edges, entries):
                    if r.map_key_id not in tracked:
                        tracked.append(r.map_key_id)
                        values.append(r.map_key)
                        edges.append([(pred, edge)])
                    else:
                        edges[tracked.index(r.map_key_id)].append((pred, edge))
                new_ptr = copy.copy(first)
                new_ptr.map_key    = JoinValue(block_idx=self.num, reg_num=reg_num,
                                               values=values, edges=edges)
                new_ptr.map_key_id = self.new_ptr_id()
                new_ptr.checked_null = nullity
                self.sources.append(new_ptr.map_key)
                return self._stamp_null_phi(new_ptr, pred_edges, entries, reg_num)
            else:
                if any(r != first for r in entries):
                    return None
                out = _with_nullity(first, nullity)
                if (first.ptr_type == PTR_TO_CTX
                        and any(r.base_id != first.base_id for r in entries)):
                    out = _with_view(out, None)
                return self._stamp_null_phi(out, pred_edges, entries, reg_num)

        else:
            if any(isinstance(r, PTR) for r in entries):
                return None
            if isinstance(first, num) and all(isinstance(r, num)
                                    and r.num == first.num for r in entries):
                return first
            if any(r is not first for r in entries):
                values = []
                edges = []
                for (pred, edge), r in zip(pred_edges, entries):
                    if r not in values:
                        values.append(r)
                        edges.append([(pred, edge)])
                    else:
                        edges[values.index(r)].append((pred, edge))
                phi = JoinValue(block_idx=self.num,
                                reg_num=reg_num, values=values, edges=edges)
                self.sources.append(phi)
                return phi
            return first


    def merge_predecessors(self, blocks: list[Block]) -> None:
        pred_edges = [(pred, 'fall' if blocks[pred].succ_f == self.num else 'taken')
                      for pred in self.preds]
        pred_blocks = [blocks[pred] for pred, edge in pred_edges]
        pred_conds = [(pb.cond_f if edge == 'fall' else pb.cond_t)
                      for pb, (pred, edge) in zip(pred_blocks, pred_edges)]

        for i in range(len(pred_blocks)):
            pb = pred_blocks[i]
            cond_p = pred_conds[i]

            pkt_base_id_p = pb.pkt_base_id


            cond_base_id = None
            cond_pkt_base_id = None
            cond_pkt_id = None
            if cond_p is not None:
                if isinstance(cond_p, PtrFacts):
                    cond_base_id = cond_p.base_id
                elif isinstance(cond_p, AdjustFacts):
                    pkt_base_id_p = cond_p.base_id
                elif isinstance(cond_p, PktFacts):
                    cond_pkt_base_id = cond_p.base_id
                    cond_pkt_id = cond_p.id

            for base_id, fact in pb.ptr_facts.items():
                if cond_base_id == base_id:
                    fact = cond_p
                if base_id not in self.ptr_facts:
                    self.ptr_facts[base_id] = PtrFacts(base_id=fact.base_id, ptr=fact.ptr, checked_null=fact.checked_null)
                else:
                    if self.ptr_facts[base_id].checked_null != fact.checked_null:
                        self.ptr_facts[base_id] = PtrFacts(base_id=fact.base_id, ptr=fact.ptr, checked_null=None)

            if i == 0:
                self.pkt_base_id = pkt_base_id_p
                for id, fact in pb.pkt_ptr_facts.items():
                    self.pkt_ptr_facts[id] = PktFacts(id=fact.id, base_id=fact.base_id,
                                        ptr=fact.ptr, min_len=fact.min_len, max_len=fact.max_len)
            elif self.pkt_base_id != pkt_base_id_p:
                self.pkt_base_id = None
                self.pkt_ptr_facts = {}
            else:
                for id, fact in pb.pkt_ptr_facts.items():
                    if cond_pkt_base_id == self.pkt_base_id and cond_pkt_id == id:
                        fact = cond_p
                    if id not in self.pkt_ptr_facts:
                        self.pkt_ptr_facts[id] = PktFacts(id=fact.id, base_id=fact.base_id,
                                        ptr=fact.ptr, min_len=fact.min_len, max_len=fact.max_len)
                    else:
                        present = self.pkt_ptr_facts[id]
                        new_min = min(fact.min_len, present.min_len) if fact.min_len is not None and present.min_len is not None else None
                        new_max = max(fact.max_len, present.max_len) if fact.max_len is not None and present.max_len is not None else None
                        self.pkt_ptr_facts[id] = PktFacts(id=fact.id, base_id=fact.base_id,
                                        ptr=fact.ptr, min_len=new_min, max_len=new_max)

        for i in range(11):
            self.regs[i] = pred_blocks[0].regs[i]
        for reg_num in range(10):
            regs = [pb.regs[reg_num] for pb in pred_blocks]

            self.regs[reg_num] = self.merge_entry(pred_edges, regs, reg_num, pred_conds)

        stk_size = min((len(pb.stk) for pb in pred_blocks), default=0)
        self.stk = [None] * stk_size
        for i in range(len(self.stk)):
            entries = [pb.stk[i] for pb in pred_blocks]
            self.stk[i] = self.merge_entry(pred_edges, entries, -8*(i+1), pred_conds)


    def stk_store(self, addr: int, size: int, value, verbose: bool = False) -> None:
        slot_idx = -(addr // 8) - 1
        slot_off = addr % 8

        if len(self.stk) < slot_idx + 1:
            for _ in range(slot_idx + 1 - len(self.stk)):
                self.stk.append(None)
            self.stk_size = slot_idx + 1

        new_value = value
        if size < 8:
            new_value = ALUbinary(op=AND, dst=new_value,
                                  src=num(num=(1 << (size*8)) - 1, size=8),
                                  idx=self.idx)
        if slot_off != 0:
            new_value = ALUbinary(op=LSH, dst=new_value,
                                  src=num(num=slot_off*8, size=8), idx=self.idx)

        old = self.stk[slot_idx]
        if old is None or (slot_off == 0 and size >= 8):
            self.stk[slot_idx] = new_value
            return

        keep = ((1 << 64) - 1) ^ (((1 << (size*8)) - 1) << (slot_off*8))
        self.stk[slot_idx] = ALUbinary(
            op=OR,
            dst=ALUbinary(op=AND, dst=old, src=num(num=keep, size=8),
                          idx=self.idx),
            src=new_value, idx=self.idx)

    def stk_load(self, addr: int, size: int, verbose: bool = False) -> Expr:
        slot_idx = -(addr // 8) - 1
        slot_off = addr % 8

        if slot_off + size > 8:
            num_slots = (slot_off + size + 7) // 8
            chunks = [self.stk[slot_idx - i] if 0 <= slot_idx - i < len(self.stk)
                      else None
                      for i in range(num_slots)]
            return ByteSeq(chunks, size, off=slot_off)

        slot = self.stk[slot_idx]

        if slot_off != 0:
            return ByteSeq((slot,), size, off=slot_off)

        slot_size = 8 if isinstance(slot, PTR) else slot.size
        if size >= slot_size or isinstance(slot, PTR):
            return slot
        return ALUbinary(op=AND, dst=slot,
                         src=num(num=(1 << (size*8)) - 1, size=size), idx=self.idx)
