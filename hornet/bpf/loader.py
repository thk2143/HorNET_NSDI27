from __future__ import annotations
import logging
import struct as _struct
from elftools.elf.elffile import ELFFile, SymbolTableSection

from bpf.constants import BPF_MAP_TYPE_PROG_ARRAY
from bpf.instr import Instr

log = logging.getLogger(__name__)

MAP_DEF_SIZE  = 20
MAP_DEF_FIELDS = ('type', 'key_size', 'value_size', 'max_entries', 'flags')


def _fail(msg: str, *args) -> None:
    log.error(msg, *args)
    exit(1)


def _section_index(elf, name: str):
    idx = None
    for i, section in enumerate(elf.iter_sections()):
        if section.name == name:
            idx = i
    return idx


_EXTRA_FIXED = {1: 4, 3: 12, 14: 4, 17: 4}
_EXTRA_VLEN  = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}


def _btf_type_size(types: list, type_id: int) -> int:
    if type_id == 0:
        return 0
    t, kind = types[type_id], types[type_id]['kind']
    if kind in (1, 4, 5, 6, 16, 19):
        return t['size_or_type']
    if kind == 2:
        return 8
    if kind == 3:
        return _btf_type_size(types, t['extra']['elem_type']) * t['extra']['nelems']
    if kind in (8, 9, 10, 11, 18):
        return _btf_type_size(types, t['size_or_type'])
    return 0


def _parse_btf(btf_data: bytes) -> list:
    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, _str_len = \
        _struct.unpack_from('<HBBIIIII', btf_data, 0)
    if magic != 0xEB9F:
        raise ValueError(f"Invalid BTF magic: {magic:#x}")

    str_base, pos = hdr_len + str_off, hdr_len + type_off
    type_end = pos + type_len

    def get_str(off: int) -> str:
        end = btf_data.index(b'\x00', str_base + off)
        return btf_data[str_base + off:end].decode('utf-8')

    types: list = [None]
    while pos < type_end:
        name_off, info, size_or_type = _struct.unpack_from('<III', btf_data, pos)
        pos += 12
        vlen, kind = info & 0xFFFF, (info >> 24) & 0x1F

        n = _EXTRA_FIXED.get(kind, _EXTRA_VLEN.get(kind, 0) * vlen)
        blob, pos = btf_data[pos:pos + n], pos + n

        if kind == 1:
            extra = _struct.unpack('<I', blob)[0]
        elif kind == 3:
            extra = dict(zip(('elem_type', 'index_type', 'nelems'),
                             _struct.unpack('<3I', blob)))
        elif kind in (4, 5):
            extra = [{'name': get_str(o), 'type': t, 'offset': off}
                     for o, t, off in _struct.iter_unpack('<3I', blob)]
        elif kind == 14:
            extra = {'linkage': _struct.unpack('<I', blob)[0]}
        elif kind == 15:
            extra = [{'type': t, 'offset': o, 'size': s}
                     for t, o, s in _struct.iter_unpack('<3I', blob)]
        else:
            extra = None

        types.append({'name': get_str(name_off), 'kind': kind, 'vlen': vlen,
                      'kind_flag': (info >> 31) & 1, 'size_or_type': size_or_type,
                      'extra': extra})

    return types


_UINT_MEMBERS = {'type': 'type', 'max_entries': 'max_entries', 'map_flags': 'flags',
                 'key_size': 'key_size', 'value_size': 'value_size'}
_TYPE_MEMBERS = {'key': 'key_size', 'value': 'value_size'}


def _parse_maps_btf(elf) -> list[dict]:
    btf_section = elf.get_section_by_name('.BTF')
    if not btf_section:
        raise ValueError("decode_binary: .maps is BTF-format but no .BTF section found")

    types = _parse_btf(btf_section.data())
    log.debug("Parsed %d BTF types", len(types) - 1)

    datasec = next((t for t in types[1:]
                    if t and t['kind'] == 15 and t['name'] == '.maps'), None)
    if datasec is None:
        log.debug("No BTF_KIND_DATASEC named '.maps' found")
        return []

    maps: list[dict] = []
    for map_id, sec_info in enumerate(datasec['extra']):
        var_type = types[sec_info['type']]
        if var_type['kind'] != 14:
            continue
        struct_type = types[var_type['size_or_type']]
        if struct_type['kind'] != 4:
            continue

        info = {'id': map_id, 'name': var_type['name'], 'type': 0, 'key_size': 0,
                'value_size': 0, 'max_entries': 0, 'flags': 0}

        for member in struct_type['extra']:
            mtype = types[member['type']]
            if mtype['kind'] != 2:
                continue
            name, pointed_id = member['name'], mtype['size_or_type']
            if name in _UINT_MEMBERS:
                if types[pointed_id]['kind'] == 3:
                    info[_UINT_MEMBERS[name]] = types[pointed_id]['extra']['nelems']
            elif name in _TYPE_MEMBERS:
                info[_TYPE_MEMBERS[name]] = _btf_type_size(types, pointed_id)

        if info['type'] == BPF_MAP_TYPE_PROG_ARRAY:
            info['key_size']   = info['key_size']   or 4
            info['value_size'] = info['value_size'] or 4

        maps.append(info)
        _log_map(info)

    return maps


def _log_map(info: dict) -> None:
    log.debug("Map %d '%s': type=%d, key_size=%d, value_size=%d, "
              "max_entries=%d, flags=%d", info['id'], info['name'], info['type'],
              info['key_size'], info['value_size'], info['max_entries'], info['flags'])


def parse_instrs(elf, symtab, main_func: str) -> tuple[list[Instr], object, int, int]:
    sym = symtab.get_symbol_by_name(main_func)
    if sym is None:
        _fail("No symbol named '%s'", main_func)
    sym = sym[0]

    base_addr = sym.entry['st_value'] // 8
    main_text = elf.get_section(sym.entry['st_shndx'])
    if main_text is None:
        _fail("No main program section found in binary")

    main_data: bytes = main_text.data()
    main_data_size   = len(main_data)
    if main_data_size % 8 != 0:
        _fail("Text section size is not a multiple of 64 bits")

    log.debug("Section '%s': %d bytes", main_text.name, main_data_size)

    instrs: list[Instr] = []
    i = idx = 0
    while main_data:
        size = 16 if main_data[0] == 0x18 else 8
        instrs.append(Instr(idx=idx, addr=i + base_addr, bytecode=main_data[:size]))
        main_data = main_data[size:]
        i, idx = i + 8, idx + 1

        if size == 16:
            instrs.append(Instr(idx=idx, addr=i + base_addr, nop=True))
            i, idx = i + 8, idx + 1

    log.debug("Decoded %d instructions", len(instrs))
    return instrs, main_text, main_data_size, sym.entry['st_value'] // 8


def parse_maps(elf, symtab) -> list[dict]:
    sec_name = '.maps'
    section  = elf.get_section_by_name(sec_name)
    if section is None:
        sec_name = 'maps'
        section  = elf.get_section_by_name(sec_name)

    data = section.data() if section else None
    if not data:
        log.debug("No '.maps'/'maps' section found")
        return []
    log.debug("Section '%s': %d bytes", sec_name, len(data))

    if not any(data):
        log.debug("'%s' is all zeros — parsing from BTF", sec_name)
        return _parse_maps_btf(elf)

    log.debug("Parsing maps from traditional format")
    maps_idx = _section_index(elf, sec_name)
    names = {int(s.entry['st_value']) // MAP_DEF_SIZE: s.name
             for s in symtab.iter_symbols() if s.entry['st_shndx'] == maps_idx}

    maps: list[dict] = []
    for mi in range(len(data) // MAP_DEF_SIZE):
        values = _struct.unpack_from('<5I', data, mi * MAP_DEF_SIZE)
        info = {'id': mi, 'name': names.get(mi), **dict(zip(MAP_DEF_FIELDS, values))}
        maps.append(info)
        _log_map(info)

    return maps


def _object_symbols(elf, symtab, sec_name: str) -> tuple[int | None, dict]:
    if not elf.get_section_by_name(sec_name):
        return None, {}
    idx = _section_index(elf, sec_name)
    syms = {s.name: {'size': s['st_size'], 'offset': s['st_value']}
            for s in symtab.iter_symbols()
            if s['st_shndx'] == idx and s['st_info']['type'] == 'STT_OBJECT'}
    log.debug("Section '%s' (idx=%d): %d symbol(s)", sec_name, idx, len(syms))
    return idx, syms


def parse_rodata(elf, symtab) -> dict:
    idx, syms = _object_symbols(elf, symtab, '.rodata')
    if idx is None:
        return {}
    return {'data': elf.get_section_by_name('.rodata').data(),
            'section_idx': idx, **syms}


def parse_bss(elf, symtab) -> dict:
    return _object_symbols(elf, symtab, '.bss')[1]


def apply_relocations(elf, symtab, instrs, bss, main_text, main_data_size, maps):
    reloc_text = elf.get_section_by_name(f'.rel{main_text.name}')
    if not reloc_text:
        log.debug("No relocation section found")
        return

    log.debug("Section '.rel%s': %d bytes", main_text.name, len(reloc_text.data()))

    for reloc in reloc_text.iter_relocations():
        r_offset = reloc['r_offset']
        if r_offset >= main_data_size:
            log.debug("  skip: offset %d outside main section", r_offset)
            continue

        symbol   = symtab.get_symbol(reloc['r_info_sym'])
        st_shndx = symbol['st_shndx']
        if isinstance(st_shndx, str) or st_shndx == 0 or st_shndx > 100:
            log.debug("  skip: special section index %s", st_shndx)
            continue

        section  = elf.get_section(st_shndx)
        sec_name = section.name if section else None
        sym_type = symbol['st_info']['type']
        r_line   = r_offset // 8

        if sym_type == 'STT_OBJECT' and sec_name in ('maps', '.maps'):
            map_id = next((i for i, m in enumerate(maps)
                           if m.get('name') == symbol.name), None)
            if map_id is None:
                maps_sec = elf.get_section_by_name('.maps')
                stride = (len(maps_sec.data()) // len(maps)
                          if maps_sec and maps else MAP_DEF_SIZE)
                map_id = symbol['st_value'] // stride
            instrs[r_line].set_reloc_tag(map_id)
            log.debug("  → map reloc: instr[%d].reloc_tag=%s",
                      r_line, instrs[r_line].reloc_tag)

        elif sec_name == '.bss' and sym_type in ('STT_SECTION', 'STT_OBJECT'):
            addr = symbol['st_value'] + instrs[r_line].imm
            key, base = _object_at(bss, addr)
            instrs[r_line].set_reloc_tag(tag=key, region=1, bss_offset=addr - base)
            log.debug("  → bss reloc: instr[%d].reloc_tag=%s+%d",
                      r_line, key, addr - base)

        elif sec_name == '.rodata' and sym_type in ('STT_SECTION', 'STT_OBJECT'):
            addr = symbol['st_value'] + instrs[r_line].imm
            instrs[r_line].set_reloc_tag(tag='rodata', region=2, rodata_offset=addr)
            log.debug("  → rodata reloc: instr[%d] offset=%d", r_line, addr)


def _object_at(objects: dict, addr: int) -> tuple:
    for name, o in objects.items():
        if o['offset'] <= addr < o['offset'] + max(o['size'], 1):
            return name, o['offset']
    return None, addr


class Loader:
    def __init__(self, file_path: str, main_func: str, verbose: bool = False):
        self.file_path = file_path
        self.main_func = main_func
        self.verbose   = verbose

    def decode_binary(self) -> dict:
        file_path = self.file_path
        main_func = self.main_func
        verbose   = self.verbose

        if verbose:
            log.setLevel(logging.DEBUG)
            if not log.handlers:
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter('%(funcName)s: %(message)s'))
                log.addHandler(handler)
                log.propagate = False

        log.debug("Decoding '%s' from %s", main_func, file_path)

        with open(file_path, 'rb') as f:
            elf = ELFFile(f)

            symtab: SymbolTableSection = elf.get_section_by_name('.symtab')
            if symtab is None:
                _fail("No .symtab section in the object file")

            instrs, main_text, main_data_size, entry_idx = parse_instrs(
                elf, symtab, main_func)
            maps   = parse_maps(elf, symtab)
            rodata = parse_rodata(elf, symtab)
            bss    = parse_bss(elf, symtab)
            apply_relocations(elf, symtab, instrs, bss, main_text, main_data_size, maps)

        return {'instrs': instrs, 'maps': maps, 'rodata': rodata, 'bss': bss,
                'entry': main_func, 'entry_idx': entry_idx, 'path': file_path,
                'section': main_text.name}
