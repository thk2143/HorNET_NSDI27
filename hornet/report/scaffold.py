from __future__ import annotations

from typing import Optional

from report.facts import BlockFact, ProgramFacts

_HOWTO = [
    "This spec runs as-is. Everything under block_conditions is DISABLED: a "
    "name starting with '_' is skipped by the parser, so delete the leading "
    "underscore to turn one on.",
    "Keys starting with '_' are annotations and are never parsed — the "
    "'_cfg' / '_when_taken' / '_reads' / '_calls' / '_atoms' lines describe "
    "the block and list atoms you can paste into its 'cond'.",
    "input.maps is empty on purpose: a map not listed there is SYMBOLIC, so "
    "both its hit and its miss paths stay reachable. See the per-map notes.",
]


def spec_scaffold(f: ProgramFacts, blocks: Optional[list[int]] = None) -> dict:
    chosen = ([b for b in f.blocks if b.num in set(blocks)] if blocks is not None
              else f.interesting_blocks())
    return {
        '_hornet':  _header(f),
        '_howto':   _HOWTO,
        'input':    _input(f),
        'block_conditions': {f'_b{b.num}': _block_condition(b) for b in chosen},
        'exit_conditions':  _exit_conditions(f),
    }


def _header(f: ProgramFacts) -> dict:
    return {
        'object': f.object_path, 'entry': f.entry,
        'instructions': f.n_instrs, 'blocks': f.n_blocks,
        'acyclic': f.acyclic,
        'return_codes': f.ret_codes,
        'generated_by': 'hornet --spec-init',
    }


def _input(f: ProgramFacts) -> dict:
    depth = max((o + s for o, s, _ in f.pkt_reads), default=0)
    read_fields = [n for _, _, n in f.pkt_reads if n]
    node: dict = {}
    if f.pkt_reads:
        node['_packet'] = ('layers only — no field is pinned, so every byte stays '
                           'symbolic. Fields this program reads: '
                           + (' '.join(read_fields) if read_fields else '(none named)'))
        node['packet'] = f.packet_template()
        node['_context'] = (f'the deepest byte read is at offset {depth}; bytes past '
                            f'the scapy expression up to pkt_len are in bounds but '
                            f'symbolic')
        node['context'] = {'pkt_len': max(depth, 54)}
    else:
        node['context'] = {'pkt_len': 64}
    node['maps'] = _maps(f)
    return node


def _maps(f: ProgramFacts) -> dict:
    out: dict = {}
    for m in f.maps:
        if not m.lookups:
            continue
        sites = ' '.join(f'b{c.block_num}' for c in m.lookups)
        head  = (f'{m.type_name}  key {m.key_size}B  value {m.value_size}B  '
                 f'max_entries {m.max_entries}  looked up at {sites}')
        if m.needs_seed:
            tail = (f'. Unlisted (as now) it is symbolic: hit and miss are both '
                    f'reachable. Add "{m.name}": {{"<key>": "<value>"}} to pin '
                    f'contents, or "{m.name}": {{}} to pin it empty — an empty '
                    f'HASH map never hits, which makes the hit-path blocks '
                    f'unreachable and any assert:"all" there vacuous.')
        else:
            tail = ('. ARRAY family: every key below max_entries is present '
                    'regardless, so listing it only pins the VALUES.')
        out[f'_{m.name}'] = head + tail
    return out


def _block_condition(b: BlockFact) -> dict:
    node: dict = {'block': b.num}
    if b.prog_entry:
        node['_program'] = (f'entry of {b.prog_entry}, reached only by a tail '
                            f'call — this block is where "did that transfer '
                            f'happen" is asked')
    node['_cfg'] = (f'{b.kind}  instrs {b.start}-{b.end}  '
                    f'preds {b.preds_text}  {b.edges}')
    if b.cond:
        node['_when_taken'] = b.cond
    if b.ret_codes is not None:
        node['_returns'] = b.ret_codes
    elif b.ret is not None:
        node['_returns'] = b.ret
    if b.reads:
        node['_reads'] = [f'@{r.idx} {r.text}' for r in b.reads]
    if b.calls:
        node['_calls'] = [f'@{c.idx} {c.text}' for c in b.calls]
    if b.phis:
        node['_phis'] = f'{b.phis} value(s) merged from predecessors'
    if b.writes:
        node['_writes'] = sorted(set(b.writes))

    atoms = [a for a in ([c.atom() for c in b.calls]
                         + [r.atom() for r in b.reads]) if a]
    if atoms:
        node['_atoms'] = atoms
    pointer = [c.atom() for c in b.calls if c.returns == 'pointer']

    node['assert'] = 'exists'
    if pointer:
        node['_cond'] = ('assert "exists" asks whether the hit path is reachable '
                         'at all — the useful first question, and it passes while '
                         'the map is symbolic. Switch to "all" to demand that '
                         'EVERY path reaching this block hit, or negate with '
                         '{"not": ...} to demand it miss.')
        node['cond'] = pointer[0] if len(pointer) == 1 else {'and': pointer}
    else:
        node['_cond'] = ('no cond: as written this asserts only that the block is '
                         'reachable. Paste one of _atoms in as "cond" (a "value" of '
                         '0 there is a placeholder) to assert something about it.')
        node['cond'] = {'and': []}
    return node


def _exit_conditions(f: ProgramFacts) -> dict:
    codes = f.ret_codes
    if not codes:
        return {'_observed_returns': {
            'assert': 'all',
            '_note': ('no exit folded to a constant return code — write a `ret` '
                      'atom by hand'),
            'cond': {'and': []}}}
    cond = {'ret': codes[0]} if len(codes) == 1 else {
        'or': [{'ret': c} for c in codes]}
    return {
        'observed_returns': {
            '_note': (f'every exit of this program returns one of {codes}; this '
                      f'holds by construction and is here as a baseline'),
            'assert': 'all', 'cond': cond},
        '_one_return_only': {
            '_note': 'narrow the baseline: pick the single code this input must give',
            'assert': 'all', 'cond': {'ret': codes[0]}},
    }
