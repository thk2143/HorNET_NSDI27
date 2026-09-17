from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from z3 import BitVec, BitVecVal, Bool, BoolVal, Concat, Extract, If, Not, Select

from verify import prune
from verify.slice import Memory, Phis
from track.record import PKT as REGION_PKT, MAP as REGION_MAP, BSS as REGION_BSS
from track.encode import (
    Z3State, _make_init_state, _and, _or_all, _bss_of, _map_key_z3, expr_to_z3,
    Condition, adjust_head_check, contain_map_value, tail_call_taken,
    AdjustHead, AdjustMeta, CtxWrite, PktWrite, MapWrite, MapUpdate, MapDelete,
    MapAtomicAdd, BssWrite, BssAtomicAdd, perf_event_output, MapLookup,
)
from track.expr import (
    pkt_val, map_val, bss_val, rodata_val, lookup_hit, func_retval, JoinValue,
    pkt_len as pkt_len_cls, rx_queue_index, ingress_ifindex, egress_ifindex,
    ALUunary, ALUbinary, ByteSeq,
)

from track.encode import BSS_ADDR_BITS


def _expr_regions(expr, out: set, seen: set) -> None:
    if expr is None or isinstance(expr, (int, str)):
        return
    eid = id(expr)
    if eid in seen:
        return
    seen.add(eid)
    if isinstance(expr, pkt_val):
        out.add(('pkt',))
        if expr.var_off is not None:
            _expr_regions(expr.var_off, out, seen)
    elif isinstance(expr, map_val):
        out.add(('map', expr.map_id))
        if expr.map_key is not None:
            _expr_regions(expr.map_key, out, seen)
        if expr.var_off is not None:
            _expr_regions(expr.var_off, out, seen)
    elif isinstance(expr, bss_val):
        out.add(('bss', expr.bss_key))
        if expr.var_off is not None:
            _expr_regions(expr.var_off, out, seen)
    elif isinstance(expr, rodata_val):
        if expr.var_off is not None:
            _expr_regions(expr.var_off, out, seen)
    elif isinstance(expr, lookup_hit):
        out.add(('map', expr.map_id))
        if expr.map_key is not None:
            _expr_regions(expr.map_key, out, seen)
    elif isinstance(expr, pkt_len_cls):
        out.add(('pkt_len',))
    elif isinstance(expr, rx_queue_index):
        out.add(('rx_index',))
    elif isinstance(expr, ingress_ifindex):
        out.add(('ingress',))
    elif isinstance(expr, egress_ifindex):
        out.add(('egress',))
    elif isinstance(expr, func_retval):
        if expr.redirects and expr.map_id is not None:
            out.add(('map', expr.map_id))
            if expr.map_key is not None:
                _expr_regions(expr.map_key, out, seen)
    elif isinstance(expr, JoinValue):
        for v in expr.values:
            _expr_regions(v, out, seen)
    elif isinstance(expr, ALUunary):
        _expr_regions(expr.dst, out, seen)
    elif isinstance(expr, ALUbinary):
        _expr_regions(expr.dst, out, seen)
        _expr_regions(expr.src, out, seen)
    elif isinstance(expr, ByteSeq):
        for c in expr.chunks:
            _expr_regions(c, out, seen)


def _branch_cond_regions(cond, out: set, seen: set) -> None:
    if cond is None:
        return
    if isinstance(cond, contain_map_value):
        if cond.map_id is not None:
            out.add(('map', cond.map_id))
            if cond.map_key is not None:
                _expr_regions(cond.map_key, out, seen)
    elif isinstance(cond, adjust_head_check):
        pass
    elif isinstance(cond, tail_call_taken):
        _expr_regions(cond.index, out, seen)
    elif isinstance(cond, Condition):
        _expr_regions(cond.dst, out, seen)
        _expr_regions(cond.src, out, seen)


def _atom_regions(atom, out: set, seen: set) -> None:
    from verify.spec import (
        PktAtom, MapAtom, BssAtom, LenAtom, ScalarAtom, HelperAtom, RetAtom, ReadAtom,
    )
    if isinstance(atom, PktAtom):
        out.add(('pkt',))
    elif isinstance(atom, MapAtom):
        out.add(('map', atom.map_id))
    elif isinstance(atom, BssAtom):
        out.add(('bss', atom.sym))
    elif isinstance(atom, LenAtom):
        out.add(('pkt_len',))
    elif isinstance(atom, ScalarAtom):
        out.add((atom.target,))
    elif isinstance(atom, HelperAtom):
        if atom.kind == 'scalar' and atom.retval is not None:
            _expr_regions(atom.retval, out, seen)
        elif atom.kind == 'map_null' and atom.map_id is not None:
            out.add(('map', atom.map_id))
            if atom.map_key is not None:
                _expr_regions(atom.map_key, out, seen)
    elif isinstance(atom, RetAtom):
        pass
    elif isinstance(atom, ReadAtom):
        for leaf, _k in atom.parts:
            _expr_regions(leaf, out, seen)


def _cond_regions(node, out: set, seen: set) -> None:
    from verify.spec import CondNode
    if isinstance(node, CondNode):
        if node.op == 'leaf':
            _atom_regions(node.atom, out, seen)
        else:
            for c in node.children:
                _cond_regions(c, out, seen)
    else:
        _atom_regions(node, out, seen)


def _write_region(action):
    if isinstance(action, PktWrite):
        return ('pkt',)
    if isinstance(action, (MapWrite, MapAtomicAdd, MapUpdate, MapDelete)):
        return ('map', action.map_id)
    if isinstance(action, (BssWrite, BssAtomicAdd)):
        return ('bss', action.bss_key)
    if isinstance(action, CtxWrite):
        return ('rx_index',)
    if isinstance(action, AdjustHead):
        return ('pkt_len',)
    return None


def _leaf_region(obj):
    if isinstance(obj, pkt_val):
        return ('pkt',)
    if isinstance(obj, map_val):
        return ('map', obj.map_id)
    if isinstance(obj, bss_val):
        return ('bss', obj.bss_key)
    if isinstance(obj, func_retval) and obj.redirects and obj.map_id is not None:
        return ('map', obj.map_id)
    return None


def relevant_regions(blocks: list, block_slice: set, cond_trees: list) -> frozenset:
    out: set = set()
    seen: set = set()
    for tree in cond_trees or ():
        _cond_regions(tree, out, seen)
    for b in block_slice:
        blk = blocks[b]
        if blk.kind == 'exit' and blk.regs[0] is not None:
            _expr_regions(blk.regs[0], out, seen)
    for b in block_slice:
        _branch_cond_regions(blocks[b].cond, out, seen)

    changed = True
    while changed:
        changed = False
        for b in block_slice:
            for a in blocks[b].actions:
                r = _write_region(a)
                if r is None or r not in out:
                    continue
                before = len(out)
                val = getattr(a, 'value', None)
                if val is not None:
                    _expr_regions(val, out, seen)
                mk = getattr(a, 'map_key', None)
                if mk is not None:
                    _expr_regions(mk, out, seen)
                vo = getattr(a, 'var_off', None)
                if vo is not None:
                    _expr_regions(vo, out, seen)
                if len(out) != before:
                    changed = True
    return frozenset(out)


def _block_slice(blocks: list, live: set, targets) -> set:
    if targets is None:
        return set(live)
    keep = {0}
    for t in targets:
        if t in live:
            keep |= prune._slice_to(blocks, live, t)
    return keep


def _region_has_var_off(blocks: list, block_slice: set) -> dict:
    out: dict = {}
    for b in block_slice:
        blk = blocks[b]
        for a in blk.actions:
            r = _write_region(a)
            if r is None or r[0] not in ('pkt', 'map', 'bss'):
                continue
            if getattr(a, 'var_off', None) is not None:
                out[r] = True
            else:
                out.setdefault(r, False)
        for s in blk.sources:
            if isinstance(s, JoinValue):
                continue
            r = _leaf_region(s)
            if r is None or r[0] not in ('pkt', 'map', 'bss'):
                continue
            if getattr(s, 'var_off', None) is not None:
                out[r] = True
            else:
                out.setdefault(r, False)
    return out


def fold_eligible_regions(blocks: list, block_slice: set, relevant: frozenset) -> frozenset:
    has_var = _region_has_var_off(blocks, block_slice)
    return frozenset(r for r in relevant
                     if r[0] in ('pkt', 'map', 'bss') and not has_var.get(r, False))


def _with_reads(sigma: Z3State, hooked: Z3State, at_block=None,
                read_loc=None) -> Z3State:
    return Z3State(pkt=sigma.pkt, map=sigma.map, bss=sigma.bss,
                   r0=sigma.r0, rx_index=sigma.rx_index,
                   ingress=sigma.ingress, egress=sigma.egress,
                   pkt_len=sigma.pkt_len, at_block=at_block,
                   read_loc=read_loc, st=hooked)


def _merge_component(pairs: list) -> Any:
    groups: list = []
    for g, term in pairs:
        for i, (og, ot) in enumerate(groups):
            if ot is term:
                groups[i] = (_or_all([og, g]), ot)
                break
        else:
            groups.append((g, term))
    if len(groups) == 1:
        return groups[0][1]
    out = groups[-1][1]
    for g, t in reversed(groups[:-1]):
        out = t if g is True else out if g is False else If(g, t, out)
    return out


def _merge_sigma(contribs: list, init_st: Z3State) -> Z3State:
    if len(contribs) == 1:
        return contribs[0][1]
    pkt = _merge_component([(g, s.pkt) for g, s in contribs])
    new_map = []
    for m in range(len(init_st.map)):
        present = _merge_component([(g, s.map[m][0]) for g, s in contribs])
        value = _merge_component([(g, s.map[m][1]) for g, s in contribs])
        new_map.append([present, value])
    bss_keys: set = set()
    for _g, s in contribs:
        bss_keys |= set((getattr(s, 'bss', None) or {}).keys())
    new_bss = {k: _merge_component([(g, _bss_of(s, k)) for g, s in contribs])
              for k in bss_keys}
    pkt_len = _merge_component([(g, s.pkt_len) for g, s in contribs])
    rx_index = _merge_component([(g, s.rx_index) for g, s in contribs])
    return Z3State(pkt=pkt, map=new_map, bss=new_bss,
                   pkt_len=pkt_len, rx_index=rx_index, st=init_st)


def _resolve_leaf(obj, sigma: Z3State, hooked: Z3State, memo: dict, at_block) -> None:
    memo[id(obj)] = expr_to_z3(obj, _with_reads(sigma, hooked, at_block))


def _branch_guards_unpruned(b, st):
    if b.cond is None:
        c = Bool(f'branch{b.num}_taken')
        return c, Not(c), True
    c = b.cond.to_z3(st)
    if c is True or c is False:
        c = BoolVal(c)
    return c, Not(c), False


@dataclass
class ForwardInfo:
    reach:      Any
    edge_taken: Any = True
    edge_fall:  Any = True
    sigma:      Optional[Z3State] = None
    imprecise:  bool = False


class ForwardContext:

    def __init__(self, blocks: list, maps: list, init_st: Z3State = None,
                calls: dict = None, targets=None, cond_trees: list = None,
                prune_paths: bool = True, resolve_values: bool = True,
                hybrid_fold: bool = True):
        Z3State.map_meta = maps
        self.prune_paths = prune_paths
        self.resolve_values = resolve_values
        self.defs: dict = {}
        self._def_closure: dict = {}
        self.blocks = blocks
        self.maps = maps
        self.calls = calls or {}
        self.init_st = init_st if init_st is not None else _make_init_state(maps)

        live = prune.forward_reachable(blocks)
        self.slice = _block_slice(blocks, live, targets)
        self.relevant = relevant_regions(blocks, self.slice, cond_trees or [])

        order = prune.topo_order(blocks, self.slice)
        self.anc = prune.ancestors(blocks, order)

        self.fold = (fold_eligible_regions(blocks, self.slice, self.relevant)
                     if resolve_values and hybrid_fold else frozenset())

        self.info: dict = {}
        self._memo: dict = {}
        self.n_stores = 0
        self._cur_block = None
        self._cur_sigma = None
        self._cur_reach = None
        self._lookup_block = {a.map_key_id: blk.num for blk in blocks
                              for a in blk.actions if isinstance(a, MapLookup)}
        self._lookup_sigma: dict = {}

        self.phis = Phis(self._edge_guard)
        self.mem = Memory(self.init_st, blocks, self.anc, self.reach)
        self.hooked = Z3State(
            read_pkt=self._read_pkt, read_map=self._read_map,
            read_bss=self._read_bss, read_present=self._read_present,
            read_fret=self._memo.get,
            read_phi=self.phis.value, st=self.init_st)
        self.phis.install(self.hooked)
        self.mem.install(self.hooked)
        self.st = self.hooked

        self._walk(order)
        self._cur_block = self._cur_sigma = self._cur_reach = None
        self._dropped: dict = {}


    def _read_pkt(self, pv):
        if ('pkt',) in self.fold:
            return self.mem.pkt(pv)
        return self._memo.get(id(pv))

    def _read_map(self, mv):
        if ('map', mv.map_id) in self.fold:
            return self.mem.map(mv)
        return self._memo.get(id(mv))

    def _read_bss(self, bv):
        if ('bss', bv.bss_key) in self.fold:
            return self.mem.bss(bv)
        return self._memo.get(id(bv))

    def _sigma_at(self, at_block) -> Z3State:
        if at_block is not None and at_block == self._cur_block:
            return self._cur_sigma
        pi = self.info.get(at_block)
        return pi.sigma if pi is not None else self.init_st

    def _read_present(self, map_id, key_z3, at_block, at_idx=None):
        blk = self._lookup_block.get(at_idx) if at_idx is not None else None
        if ('map', map_id) in self.fold:
            if blk is not None:
                return self.mem.present(map_id, key_z3, blk, at_idx)
            return self.mem.present(map_id, key_z3, at_block)
        sigma = self._lookup_sigma.get(at_idx) if blk is not None else None
        if sigma is None:
            sigma = self._sigma_at(at_block)
        return Select(sigma.map[map_id][0], key_z3)

    def _read_loc(self, region, offset, size, map_id, map_key, at_block,
                  bss_key=None):
        if region == REGION_PKT:
            if ('pkt',) in self.fold:
                return self.mem.loc_byte(region, offset, size, None, None, at_block)
            sigma = self._sigma_at(at_block)
            dom = sigma.pkt.domain().size()
            return Select(sigma.pkt, BitVecVal(offset, dom))
        if region == REGION_MAP:
            if ('map', map_id) in self.fold:
                return self.mem.loc_byte(region, offset, size, map_id, map_key, at_block)
            sigma = self._sigma_at(at_block)
            val = Select(sigma.map[map_id][1], _map_key_z3(self.hooked, map_id, map_key))
            lo = offset * 8
            if lo >= val.size():
                return BitVecVal(0, 8)
            return Extract(min(lo + 8, val.size()) - 1, lo, val)
        if region == REGION_BSS:
            if ('bss', bss_key) in self.fold:
                return self.mem.loc_byte(region, offset, size, None, None, at_block,
                                         bss_key=bss_key)
            sigma = self._sigma_at(at_block)
            return Select(_bss_of(sigma, bss_key), BitVecVal(offset, BSS_ADDR_BITS))
        return None


    def _walk(self, order: list) -> None:
        relevant = self.relevant
        fold = self.fold
        branch_guards = (prune._branch_guards if self.prune_paths
                         else _branch_guards_unpruned)
        for b in order:
            block = self.blocks[b]
            if b == 0:
                reach, sigma_entry = True, self.init_st
            else:
                contribs = []
                for p in sorted(set(block.preds)):
                    pi = self.info.get(p)
                    if pi is None or pi.reach is False:
                        continue
                    ps = self.blocks[p]
                    if ps.succ_t == b:
                        g = _and(pi.reach, pi.edge_taken)
                        if g is not False:
                            contribs.append((g, pi.sigma))
                    if ps.succ_f == b:
                        g = _and(pi.reach, pi.edge_fall)
                        if g is not False:
                            contribs.append((g, pi.sigma))
                reach = _or_all([g for g, _s in contribs])
                sigma_entry = (_merge_sigma(contribs, self.init_st)
                              if contribs else self.init_st)

            self._cur_block = b
            self._cur_reach = reach
            sigma = sigma_entry
            self._cur_sigma = sigma

            items = ([('src', s) for s in block.sources
                     if not isinstance(s, JoinValue)]
                    + [('act', a) for a in block.actions])
            items.sort(key=lambda t: (t[1].idx, 0 if t[0] == 'src' else 1))
            for kind, obj in items:
                if kind == 'src':
                    if id(obj) in self._memo:
                        continue
                    region = _leaf_region(obj)
                    if region is not None and region not in relevant:
                        continue
                    if region is not None and region in fold:
                        continue
                    if self.resolve_values:
                        _resolve_leaf(obj, sigma, self.hooked, self._memo, b)
                    else:
                        self._bind_unresolved(obj, sigma, b)
                else:
                    if isinstance(obj, MapLookup):
                        self._lookup_sigma[obj.map_key_id] = sigma
                    region = _write_region(obj)
                    if region is not None and region not in relevant:
                        continue
                    if region is not None and region in fold:
                        continue
                    sigma = obj.to_z3(_with_reads(sigma, self.hooked, b))
                    self._cur_sigma = sigma
                    self.n_stores += 1

            edge_taken = edge_fall = True
            imprecise = False
            if block.branch:
                edge_taken, edge_fall, imprecise = branch_guards(
                    block, _with_reads(sigma, self.hooked, b))

            self.info[b] = ForwardInfo(reach=reach, edge_taken=edge_taken,
                                       edge_fall=edge_fall, sigma=sigma,
                                       imprecise=imprecise)


    def _bind_unresolved(self, obj, sigma, at_block) -> None:
        term = expr_to_z3(obj, _with_reads(sigma, self.hooked, at_block))
        var = BitVec(f'read{len(self.defs)}', term.size())
        self.defs[var.get_id()] = (var, term)
        self._memo[id(obj)] = var

    def definitions(self, *roots) -> list:
        if not self.defs:
            return []
        need: dict = {}
        for root in roots:
            if root is True or root is False or root is None:
                continue
            hit = self._def_closure.get(root.get_id())
            if hit is None:
                hit = self._def_closure[root.get_id()] = (root, self._closure(root))
            need.update(hit[1])
        return [v == t for v, t in need.values()]

    def _closure(self, root) -> dict:
        out, seen, stack = {}, set(), [root]
        while stack:
            e = stack.pop()
            eid = e.get_id()
            if eid in seen:
                continue
            seen.add(eid)
            d = self.defs.get(eid)
            if d is not None:
                out[eid] = d
                stack.append(d[1])
            else:
                stack.extend(e.children())
        return out

    def _edge_guard(self, pred, kind):
        pi = self.info.get(pred)
        if pi is None:
            return False
        return _and(pi.reach, pi.edge_taken if kind == 'taken' else pi.edge_fall)


    def reach(self, block):
        if block == self._cur_block:
            return self._cur_reach
        pi = self.info.get(block)
        return False if pi is None else pi.reach

    def state_at(self, block):
        pi = self.info.get(block)
        sigma = pi.sigma if pi is not None else self.init_st
        read_loc = (lambda r, o, sz, mid, mk, bss_key=None:
                    self._read_loc(r, o, sz, mid, mk, block, bss_key))
        return _with_reads(sigma, self.hooked, block, read_loc)

    def ret_state(self, block):
        ret = self.blocks[block].ret_expr
        if ret is None:
            return None
        base = self.state_at(block)
        r0 = expr_to_z3(ret, base)
        if r0.size() < 64:
            r0 = Concat(BitVecVal(0, 64 - r0.size()), r0)
        return Z3State(r0=r0, st=base)

    def dropped_effects(self, block) -> list:
        if block in self._dropped:
            return self._dropped[block]
        reached = {block} | set(self.anc.get(block, ()))
        seen = []
        for b in sorted(reached):
            if b not in self.info or self.reach(b) is False:
                continue
            for a in self.blocks[b].actions:
                if isinstance(a, perf_event_output) and 'perf_event_output' not in seen:
                    seen.append('perf_event_output: recorded but has no state effect')
                if isinstance(a, AdjustMeta) and 'adjust_meta' not in seen:
                    seen.append('adjust_meta: recorded, but the metadata area '
                                'is not modelled')
        self._dropped[block] = seen
        return seen
