from __future__ import annotations

from dataclasses import asdict

from report.facts import BlockFact, ProgramFacts

_W = 78


def _rule(title: str = '') -> str:
    return f'── {title} ' .ljust(_W, '─') if title else '─' * _W


def report(f: ProgramFacts, blocks: bool = False) -> str:
    out = [*_program(f)]
    progs = _programs(f)
    if progs:
        out += ['', *progs]
    out += ['', *_maps(f), '', *_packet(f), '', *_exits(f)]
    if blocks:
        out += ['', *_blocks(f)]
    out += ['', *_next_steps(f)]
    return '\n'.join(out)


def _program(f: ProgramFacts) -> list[str]:
    cyc = ('acyclic' if f.acyclic else
           f'CYCLIC: back edges {f.back_edges} — the topological traversal '
           f'cannot finish')
    out = [f'program   {f.object_path}',
           f'          entry {f.entry}',
           f'  size    {f.n_instrs} instructions ({f.n_bytes} B)   '
           f'{f.n_blocks} blocks   {cyc}']
    if f.helpers:
        out.append('  helpers ' + '   '.join(
            f'{n} {c}' for n, c in sorted(f.helpers.items(), key=lambda kv: -kv[1])))
    if f.effects:
        out.append('  effects ' + '  '.join(
            f'{n} {c}' for n, c in sorted(f.effects.items(), key=lambda kv: -kv[1])))
    if f.rodata or f.bss:
        out.append(f'  globals .rodata {f.rodata} objects   .bss {f.bss} objects')
    return out


def _programs(f: ProgramFacts) -> list[str]:
    if len(f.progs) < 2:
        return []
    out = [_rule(f'programs ({len(f.progs)})')]
    out.append('  entry                 blocks     instrs  loaded at')
    for p in f.progs:
        span = (f'b{p.first_block}' if p.first_block == p.last_block
                else f'b{p.first_block}-b{p.last_block}')
        out.append(f'  {p.name:<20.20}  {span:<9} {p.n_instrs:>6}  {p.loaded_at}')
        out.append(f'     from {p.path}')
    unpinned = [p for p in f.progs if not p.is_main and p.slot is None]
    if unpinned:
        out += ['',
                '  A callee with no slot is reached under a FREE condition: both the',
                '  transfer and the failure stay satisfiable and neither is proved.',
                '  Pin it with --tail obj:entry@SLOT to decide the edge.']
    return out


def _maps(f: ProgramFacts) -> list[str]:
    out = [_rule(f'maps ({len(f.maps)})')]
    if not f.maps:
        return out + ['  (none)']
    out.append('  id name                 type          key  val  entries  lookups  seed')
    for m in f.maps:
        sites = ' '.join(f'b{c.block_num}' for c in m.lookups)
        out.append(f'  {m.id:>2} {m.name:<20.20} {m.type_name:<12.12} '
                   f'{m.key_size:>4} {m.value_size:>4} {m.max_entries:>8} '
                   f'{len(m.lookups):>8}  {"YES" if m.needs_seed else "-":<4}')
        if sites:
            out.append(f'     at {sites}')
    seeded = [m for m in f.maps if m.needs_seed]
    if seeded:
        out += ['',
                '  seed=YES: a HASH-family map starts EMPTY, so its lookups always miss',
                '  and the hit-path blocks after them are unreachable — an assert:"all"',
                '  there passes vacuously. List the map in input.maps to control it:']
        for m in seeded:
            out.append(f'    "{m.name}": {{"<{m.key_size}B key>": "<{m.value_size}B value>"}}'
                       f'   # or {{}} to pin it empty')
    return out


def _packet(f: ProgramFacts) -> list[str]:
    out = [_rule('packet bytes this program reads')]
    if not f.pkt_reads:
        out.append('  (none — the program never reads packet memory)')
    else:
        named = [(o, s, n) for o, s, n in f.pkt_reads if n]
        plain = [(o, s) for o, s, n in f.pkt_reads if not n]
        if named:
            out.append('  named  ' + '  '.join(f'{n}@{o}:{s}' for o, s, n in named))
        if plain:
            out.append('  other  ' + '  '.join(f'{o}:{s}' for o, s in plain))
        if f.var_off_reads:
            out.append(f'  {f.var_off_reads} read(s) at a computed offset — '
                       f'name those with a `read` atom, not an `offset`')
        out.append(f'  input.packet candidate:  {f.packet_template()}')
    return out


def _exits(f: ProgramFacts) -> list[str]:
    out = [_rule(f'exits ({len(f.exits)})')]
    for e in f.exits:
        codes = ('{' + ', '.join(str(c) for c in e.ret_codes) + '}'
                 if e.ret_codes is not None else f'{e.ret} (not constant-folded)')
        out.append(f'  block {e.block:<4} returns {codes}')
    codes = f.ret_codes
    if codes is not None and len(f.exits) > 1:
        out.append('  all exits: {' + ', '.join(str(c) for c in codes) + '}')
    return out


def _blocks(f: ProgramFacts) -> list[str]:
    interesting = f.interesting_blocks()
    out = [_rule(f'blocks that produce a value or call a helper '
                 f'({len(interesting)} of {f.n_blocks})')]
    for b in interesting:
        out += block_detail(b, indent='  ').splitlines() + ['']
    return out


def _next_steps(f: ProgramFacts) -> list[str]:
    return [_rule('next'),
            '  hornet -i <obj> -e <entry> -s info -b N          one block in detail',
            '  hornet -i <obj> -e <entry> -s info --all-blocks  every block',
            '  hornet -i <obj> -e <entry> --spec-init s.json    a runnable spec skeleton']


def block_detail(b: BlockFact, indent: str = '') -> str:
    i = indent
    out = [f'{i}block {b.num}  {b.kind}  instrs {b.start}-{b.end}  '
           f'preds {b.preds_text}  {b.edges}']
    if b.prog_entry:
        out.append(f'{i}  entry of {b.prog_entry} — reached only by a tail call')
    if b.cond:
        out.append(f'{i}  when taken: {b.cond}')
    if b.ret is not None:
        codes = ('{' + ', '.join(str(c) for c in b.ret_codes) + '}'
                 if b.ret_codes is not None else b.ret)
        out.append(f'{i}  returns {codes}')
    for r in b.reads:
        out.append(f'{i}  read  @{r.idx:<5} {r.text}')
    for c in b.calls:
        out.append(f'{i}  call  @{c.idx:<5} {c.text}')
    if b.phis:
        out.append(f'{i}  phis  {b.phis} value(s) merged from predecessors')
    if b.writes:
        out.append(f'{i}  write ' + '  '.join(sorted(set(b.writes))))
    atoms = [a for a in ([c.atom() for c in b.calls]
                         + [r.atom() for r in b.reads]) if a]
    if atoms:
        out.append(f'{i}  atoms for a block_conditions cond:')
        for a in atoms:
            out.append(f'{i}    {a}')
    return '\n'.join(out)


def to_json(f: ProgramFacts, blocks: bool = True) -> dict:
    def _map(m):
        d = {k: v for k, v in asdict(m).items() if k not in ('lookups', 'reads')}
        d['family']     = m.family
        d['needs_seed'] = m.needs_seed
        d['lookups']    = [{'idx': c.idx, 'block': c.block_num} for c in m.lookups]
        d['value_reads'] = [{'idx': r.idx, 'off': r.off, 'size': r.size}
                            for r in m.reads]
        return d

    def _block(b):
        d = asdict(b)
        d['reads'] = [{**asdict(r), 'text': r.text} for r in b.reads]
        d['calls'] = [{**asdict(c), 'text': c.text} for c in b.calls]
        return d

    out = {
        'object': f.object_path, 'entry': f.entry,
        'size': {'instructions': f.n_instrs, 'bytes': f.n_bytes,
                 'blocks': f.n_blocks, 'rodata_objects': f.rodata,
                 'bss_objects': f.bss},
        'cfg': {'acyclic': f.acyclic, 'back_edges': f.back_edges},
        'programs': [asdict(p) for p in f.progs],
        'helpers': f.helpers, 'effects': f.effects,
        'maps': [_map(m) for m in f.maps],
        'packet_reads': [{'off': o, 'size': s, 'field': n} for o, s, n in f.pkt_reads],
        'var_offset_reads': f.var_off_reads,
        'packet_template': f.packet_template(),
        'exits': [asdict(e) for e in f.exits],
        'return_codes': f.ret_codes,
    }
    if blocks:
        out['blocks'] = [_block(b) for b in f.blocks]
    return out
