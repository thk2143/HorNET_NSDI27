from __future__ import annotations

from z3 import BitVec, BitVecVal, Bool, BoolVal, Concat, Extract, If, Select, ULT

from track.record import _const, may_alias, PKT, MAP, BSS
from track.encode import (AdjustHead, CtxWrite, MapUpdate, Z3State, _and,
                          _is_array_map, _map_info, _map_key_z3, _or_all,
                          _resize, expr_to_z3, update_applies)


class Memory:

    def __init__(self, init_st: Z3State, blocks: list, anc: dict, reach_of):
        self.init = init_st
        self.blocks = blocks
        self.anc = anc
        self.reach_of = reach_of
        self._cache: dict = {}
        self._keyz3: dict = {}
        self._applies_memo: dict = {}
        self.resolved = 0
        self.direct = 0
        self.st = init_st

        self.writes = [a for b in blocks for a in b.actions
                       if a.region is not None]
        self.presence_writes = [a for b in blocks for a in b.actions
                                if a.presence is not None]
        self.adjusts = [a for b in blocks for a in b.actions
                        if isinstance(a, AdjustHead)]
        self.ctx_writes = [a for b in blocks for a in b.actions
                           if isinstance(a, CtxWrite)]

    def install(self, st):
        self.st = st
        return st


    def pkt(self, pv):
        if pv.var_off is not None:
            return None
        return self._read(PKT, pv.off, pv.size, None, None, pv.block, pv.idx)

    def map(self, mv):
        return self._read(MAP, mv.off, mv.size, mv.map_id, mv.map_key,
                          mv.block, mv.idx)

    def bss(self, bv):
        if bv.var_off is not None:
            return None
        return self._read(BSS, bv.off, bv.size, None, None, bv.block, bv.idx,
                          bss_key=bv.bss_key)

    def _write_guard(self, loc, w):
        g = self.reach_of(w.block)
        if g is not False and isinstance(w, MapUpdate):
            g = _and(g, self._applies(w))
        if loc.region != MAP or g is False:
            return g
        ka, kb = _const(loc.map_key), _const(w.map_key)
        if ka is not None and kb is not None:
            return g
        if loc.map_key is None or w.map_key is None:
            return g
        if loc.map_key is w.map_key:
            return g
        return _and(g, self._key(loc.map_id, loc.map_key) ==
                      self._key(w.map_id, w.map_key))

    def _key(self, map_id, key_expr):
        ck = (map_id, id(key_expr))
        hit = self._keyz3.get(ck)
        if hit is None or hit[0] is not key_expr:
            hit = self._keyz3[ck] = (key_expr, _map_key_z3(self.st, map_id, key_expr))
        return hit[1]

    def _applies(self, w):
        if w.flags is not None and w.flags & 3 == 0:
            return True
        hit = self._applies_memo.get(id(w))
        if hit is not None and hit[0] is w:
            return hit[1]
        key = self._key(w.map_id, w.map_key)
        info = _map_info(self.st, w.map_id)
        if info is not None and _is_array_map(self.st, w.map_id):
            p = ULT(key, BitVecVal(info['max_entries'], key.size()))
        else:
            p = self.present(w.map_id, key, w.block, w.idx)
        out = update_applies(w, p)
        self._applies_memo[id(w)] = (w, out)
        return out

    def _visible(self, w, at_block: int, at_idx: int) -> bool:
        if w.block != at_block and w.block not in self.anc.get(at_block, ()):
            return False
        if w.block == at_block and w.idx >= at_idx:
            return False
        return self.reach_of(w.block) is not False

    def _read(self, region, off, size, map_id, map_key, at_block, at_idx,
              bss_key=None):
        key = (region, off, size, map_id, id(map_key), at_block, at_idx, bss_key)
        hit = self._cache.get(key)
        if hit is not None and hit[0] is map_key:
            return hit[1]

        seen_write = False
        terms = []
        for i in range(size):
            loc = _Loc(region, off + i, 1, map_id, map_key, bss_key)
            term = self._initial_at(loc)
            if term is None:
                return None
            for w in self.writes:
                if not self._visible(w, at_block, at_idx) or not may_alias(loc, w):
                    continue
                seen_write = True
                v = self._written_byte(w, off + i)
                if v is None:
                    continue
                g = self._write_guard(loc, w)
                term = v if g is True else term if g is False else If(g, v, term)
            terms.append(term)

        if seen_write: self.resolved += 1
        else:          self.direct += 1
        terms.reverse()
        out = Concat(*terms) if len(terms) > 1 else terms[0]
        self._cache[key] = (map_key, out)
        return out

    def loc_byte(self, region, offset, size, map_id, map_key, at_block,
                 bss_key=None):
        loc = _Loc(region, offset, size, map_id, map_key, bss_key)
        term = self._initial_at(loc)
        if term is None:
            return None
        for w in self.writes:
            if w.block != at_block and w.block not in self.anc.get(at_block, ()):
                continue
            if self.reach_of(w.block) is False or not may_alias(loc, w):
                continue
            v = self._written_byte(w, offset)
            if v is None:
                continue
            g = self._write_guard(loc, w)
            term = v if g is True else term if g is False else If(g, v, term)
        return term

    def _initial_at(self, loc):
        st = self.st
        if loc.region == PKT:
            dom = st.pkt.domain().size()
            return Select(st.pkt, BitVecVal(loc.off, dom))
        if loc.region == MAP:
            val = Select(st.map[loc.map_id][1],
                         _map_key_z3(st, loc.map_id, loc.map_key))
            lo = loc.off * 8
            if lo + 8 <= val.size():
                return Extract(lo + 7, lo, val)
            return BitVecVal(0, 8)
        if loc.region == BSS:
            from track.encode import _bss_of, BSS_ADDR_BITS
            return Select(_bss_of(st, loc.bss_key),
                          BitVecVal(loc.off, BSS_ADDR_BITS))
        return None


    def _ran_before(self, w, at_block) -> bool:
        if w.block != at_block and w.block not in self.anc.get(at_block, ()):
            return False
        return self.reach_of(w.block) is not False

    def present(self, map_id, key_z3, at_block, at_idx=None):
        p = Select(self.st.map[map_id][0], key_z3)
        if at_block is None:
            return p
        for w in self.presence_writes:
            if w.map_id != map_id:
                continue
            if not (self._ran_before(w, at_block) if at_idx is None
                    else self._visible(w, at_block, at_idx)):
                continue
            g = self.reach_of(w.block)
            if w.map_key is not None:
                g = _and(g, self._key(map_id, w.map_key) == key_z3)
            if g is not False and isinstance(w, MapUpdate):
                g = _and(g, self._applies(w))
            if g is False:
                continue
            new = BoolVal(bool(w.presence))
            p = new if g is True else If(g, new, p)
        return p

    def pkt_len_at(self, at_block):
        n = self.st.pkt_len
        if at_block is None:
            return n
        for w in self.adjusts:
            if not self._ran_before(w, at_block):
                continue
            g = _and(self.reach_of(w.block),
                     True if w.idx < 0 else Bool(f'adjust{w.idx}_ok'))
            if g is False:
                continue
            shifted = n - BitVecVal(w.len_delta, n.size())
            n = shifted if g is True else If(g, shifted, n)
        return n

    def rx_index_at(self, at_block):
        v = self.st.rx_index
        if at_block is None:
            return v
        for w in self.ctx_writes:
            if not self._ran_before(w, at_block):
                continue
            g = self.reach_of(w.block)
            if g is False:
                continue
            new = _resize(expr_to_z3(w.value, self.st), v.size())
            v = new if g is True else If(g, new, v)
        return v

    def _written_byte(self, w, offset: int):
        if w.var_off is not None or not (w.off <= offset < w.off + max(w.size, 1)):
            return None
        width = max(w.size, 1) * 8
        val = _resize(expr_to_z3(w.value, self.st), width)
        old = getattr(w, 'old', None)
        if old is not None:
            val = _resize(expr_to_z3(old, self.st), width) + val
        lo = (offset - w.off) * 8
        return Extract(lo + 7, lo, val)


class _Loc:
    __slots__ = ('region', 'off', 'var_off', 'size', 'map_id', 'map_key',
                 'bss_key')

    def __init__(self, region, off, size, map_id, map_key, bss_key=None):
        self.region, self.off, self.size = region, off, size
        self.var_off = None
        self.map_id, self.map_key = map_id, map_key
        self.bss_key = bss_key


class Phis:

    def __init__(self, guard_of):
        self.guard_of = guard_of
        self._cache: dict = {}
        self._active: set = set()

    def install(self, st):
        self.st = st
        return st

    def _free(self, j):
        return BitVec(f'phi{j.block_idx}_{j.reg_num}', 64)

    def value(self, j):
        key = id(j)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        if key in self._active:
            return self._free(j)
        self._active.add(key)
        try:
            terms = []
            for val, edge_group in zip(j.values, j.edges):
                g = _or_all([self.guard_of(p, kind) for p, kind in edge_group])
                if g is False:
                    continue
                terms.append((g, _resize(expr_to_z3(val, self.st), 64)))
            if not terms:
                out = self._free(j)
            else:
                out = terms[-1][1]
                for g, t in reversed(terms[:-1]):
                    out = t if g is True else out if g is False else If(g, t, out)
        finally:
            self._active.discard(key)
        self._cache[key] = out
        return out
