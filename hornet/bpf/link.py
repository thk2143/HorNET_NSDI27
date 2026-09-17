from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from bpf.constants import BPF_MAP_TYPE_PROG_ARRAY

log = logging.getLogger(__name__)


class LinkError(Exception):
    pass


@dataclass
class TailSpec:
    path:  str
    entry: str
    map_name: Optional[str] = None
    slot:     Optional[int] = None

    def __str__(self) -> str:
        if self.slot is None:
            at = 'symbolic slot'
        elif self.map_name:
            at = f'{self.map_name}[{self.slot}]'
        else:
            at = f'slot {self.slot}'
        return f'{os.path.basename(self.path)}:{self.entry}@{at}'

    def as_flag(self) -> str:
        at = ''
        if self.map_name or self.slot is not None:
            at = '@' + (f'{self.map_name}/' if self.map_name else '') \
                     + ('' if self.slot is None else str(self.slot))
        return f'--tail {self.path}:{self.entry}{at}'


def parse_tail_spec(text: str) -> TailSpec:
    body, _, at = text.partition('@')
    path, sep, entry = body.rpartition(':')
    if not sep or not path or not entry:
        raise LinkError(f'--tail wants OBJ:ENTRY[@[MAP/]SLOT], got {text!r}')

    map_name, slot = None, None
    if at:
        map_name, sep, slot_text = at.rpartition('/')
        map_name = map_name or None
        slot_text = slot_text.strip()
        if slot_text:
            try:
                slot = int(slot_text, 0)
            except ValueError:
                raise LinkError(f'--tail slot must be a number, got {slot_text!r}')
            if slot < 0:
                raise LinkError(f'--tail slot must not be negative: {slot}')
    return TailSpec(path=path, entry=entry, map_name=map_name, slot=slot)


@dataclass
class ProgRegion:
    name:  str
    path:  str
    start: int
    end:   int
    slot:   Optional[int] = None
    map_id: Optional[int] = None
    entry_block: Optional[int] = None

    @property
    def is_main(self) -> bool:
        return self.slot is None and self.map_id is None

    def contains(self, idx: int) -> bool:
        return self.start <= idx <= self.end

    def __str__(self) -> str:
        at = '' if self.is_main else f' @map{self.map_id}[{self.slot}]'
        return f'{self.name} [{self.start}..{self.end}]{at}'


def region_of(progs, idx: int):
    for r in progs or ():
        if r.contains(idx):
            return r
    return None


def _map_key(info: dict, path: str) -> tuple:
    return (info['name'],) if info.get('name') else (path, info['id'])


_GEOMETRY = ('type', 'key_size', 'value_size', 'max_entries')


def _merge_maps(loads: list[dict]) -> tuple[list[dict], list[dict]]:
    merged: list[dict] = []
    index: dict[tuple, int] = {}
    remaps: list[dict] = []

    for load in loads:
        remap: dict[int, int] = {}
        for info in load['maps']:
            key = _map_key(info, load['path'])
            hit = index.get(key)
            if hit is None:
                new = dict(info)
                new['id'] = len(merged)
                index[key] = new['id']
                merged.append(new)
                remap[info['id']] = new['id']
                continue
            have = merged[hit]
            if any(have[f] != info[f] for f in _GEOMETRY):
                raise LinkError(
                    f"map {info['name']!r} is declared differently in "
                    f"{os.path.basename(load['path'])} than in the object it "
                    f"was first seen in: "
                    + ', '.join(f'{f}={have[f]} vs {info[f]}' for f in _GEOMETRY
                                if have[f] != info[f]))
            remap[info['id']] = hit
        remaps.append(remap)
    return merged, remaps


def _merge_globals(loads: list[dict]) -> tuple[dict, dict, list[dict], list[int]]:
    bss: dict = {}
    renames: list[dict] = []
    rodata: dict = {}
    blob = b''
    bases: list[int] = []

    for load in loads:
        rename: dict[str, str] = {}
        prefix = f"{load['entry']}."
        for name, sym in (load['bss'] or {}).items():
            have = bss.get(name)
            if have is None:
                bss[name] = dict(sym)
                continue
            if have['size'] == sym['size']:
                continue
            new = prefix + name
            bss[new] = dict(sym)
            rename[name] = new
        renames.append(rename)

        src = load['rodata'] or {}
        bases.append(len(blob))
        data = src.get('data') or b''
        for name, sym in src.items():
            if name in ('data', 'section_idx'):
                continue
            out = name if name not in rodata else prefix + name
            rodata[out] = {'size': sym['size'], 'offset': sym['offset'] + len(blob)}
        if data:
            blob += data
            if len(blob) % 8:
                blob += b'\0' * (8 - len(blob) % 8)

    if blob or len(rodata):
        rodata['data'] = blob
        rodata.setdefault('section_idx', (loads[0]['rodata'] or {}).get('section_idx'))
    return bss, rodata, renames, bases


def _retag(instrs, map_remap: dict, bss_rename: dict, rodata_base: int) -> None:
    for instr in instrs:
        if not getattr(instr, 'relocated', False):
            continue
        if instr.reloc_region == 0:
            instr.reloc_tag = map_remap.get(instr.reloc_tag, instr.reloc_tag)
        elif instr.reloc_region == 1:
            instr.reloc_tag = bss_rename.get(instr.reloc_tag, instr.reloc_tag)
        elif instr.reloc_region == 2 and rodata_base:
            instr.rodata_offset += rodata_base


def _prog_array_id(maps: list[dict], want: Optional[str], who: str) -> int:
    progs = [m for m in maps if m['type'] == BPF_MAP_TYPE_PROG_ARRAY]
    if want is not None:
        for m in progs:
            if m['name'] == want:
                return m['id']
        named = next((m for m in maps if m['name'] == want), None)
        if named is not None:
            raise LinkError(f"--tail {who}: map {want!r} is not a PROG_ARRAY "
                            f"(type={named['type']})")
        raise LinkError(f"--tail {who}: no map named {want!r}")
    if not progs:
        raise LinkError(f"--tail {who}: the main object declares no "
                        "BPF_MAP_TYPE_PROG_ARRAY map to load it into")
    if len(progs) > 1:
        names = ', '.join(m['name'] or f"map{m['id']}" for m in progs)
        raise LinkError(f"--tail {who}: which prog array? the main object has "
                        f"{len(progs)} ({names}) -- name one as MAP/SLOT")
    return progs[0]['id']


def link(loads: list[dict], tails: list[TailSpec]) -> dict:
    main = loads[0]
    if len(loads) != len(tails) + 1:
        raise LinkError(f'link: {len(loads)} object(s) but {len(tails)} --tail')

    for load, tail in zip(loads[1:], tails):
        chained = next((i.idx for i in load['instrs'] if i.is_tail_call()), None)
        if chained is not None:
            raise LinkError(
                f"--tail {tail}: {tail.entry!r} contains a bpf_tail_call of "
                f"its own (instruction {chained}). Chained tail calls are not "
                "implemented.")
        if load['entry_idx'] != 0:
            raise LinkError(
                f"--tail {tail}: {tail.entry!r} is not the first function in "
                f"section {load['section']!r} (it starts at instruction "
                f"{load['entry_idx']}). Hornet decodes a section from its "
                "start, so a callee must have its own section -- give it a "
                "distinct SEC() name.")

    maps, map_remaps = _merge_maps(loads)
    bss, rodata, bss_renames, rodata_bases = _merge_globals(loads)

    instrs: list = []
    progs:  list[ProgRegion] = []
    for i, load in enumerate(loads):
        base = len(instrs)
        body = load['instrs']
        if not body:
            raise LinkError(f"{load['path']}: {load['entry']!r} decoded to "
                            "no instructions")
        if i + 1 < len(loads) and not body[-1].is_exit():
            raise LinkError(
                f"{load['path']}: section {load['section']!r} does not end in "
                "EXIT, so control would fall out of it into the next program. "
                "Give the callee its own SEC().")
        _retag(body, map_remaps[i], bss_renames[i], rodata_bases[i])
        for instr in body:
            instr.idx = base + instr.idx
        instrs.extend(body)

        tail = tails[i - 1] if i else None
        progs.append(ProgRegion(
            name=load['entry'], path=load['path'],
            start=base, end=len(instrs) - 1,
            slot=None if tail is None else tail.slot,
            map_id=(None if tail is None else
                    _prog_array_id(maps, tail.map_name, str(tail)))))

    claimed: dict[int, ProgRegion] = {}
    for r in progs[1:]:
        clash = claimed.get(r.map_id)
        if clash is not None:
            raise LinkError(
                f"--tail: {clash.name!r} and {r.name!r} are both loaded into "
                f"{maps[r.map_id]['name']!r}. Hornet resolves a tail call to "
                "one callee per prog array, so give them separate maps.")
        claimed[r.map_id] = r

    log.debug("linked %d program(s), %d instructions, %d map(s)",
              len(progs), len(instrs), len(maps))
    return {'instrs': instrs, 'maps': maps, 'rodata': rodata, 'bss': bss,
            'progs': progs}
