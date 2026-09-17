from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

PROG_NAME     = 'hornet'
DEFAULT_ENTRY = 'xdp_prog_simple'
STAGES        = ('info', 'static', 'verify', 'all')

EXIT_OK, EXIT_VIOLATION, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3


class CliError(Exception):
    pass


@dataclass
class Config:
    input:         str
    entry:         str = DEFAULT_ENTRY
    tail:          Optional[list] = None
    constraints:   Optional[str] = None
    info_output:   Optional[str] = None
    info_json:     Optional[str] = None
    spec_init:     Optional[str] = None
    result_output: Optional[str] = None
    stage:         str = 'all'
    block:         Optional[int] = None
    spec_blocks:   Optional[str] = None
    all_blocks:    bool = False
    reach_report:  bool = False
    no_pipeline:   bool = False
    verbose:       int = 0

    @classmethod
    def from_args(cls, a: argparse.Namespace) -> 'Config':
        return cls(**{f: getattr(a, f) for f in cls.__dataclass_fields__})

    @property
    def run_info(self) -> bool:
        return self.stage in ('info', 'static', 'all')

    @property
    def run_verify(self) -> bool:
        return self.stage in ('verify', 'all')

    def log(self, msg: str, level: int = 1) -> None:
        if self.verbose >= level:
            print(f'[{PROG_NAME}] {msg}', file=sys.stderr)


def _add_input_args(g) -> None:
    g.add_argument('-i', '--input', metavar='OBJ', required=True,
                   help='eBPF object file (ELF .o) to analyze')
    g.add_argument('-e', '--entry', metavar='SYM', default=DEFAULT_ENTRY,
                   help='entry function name')
    g.add_argument('-t', '--tail', metavar='OBJ:SYM[@[MAP/]SLOT]',
                   action='append',
                   help='a bpf_tail_call target: another object file, the '
                        'entry symbol in it, and the PROG_ARRAY slot it is '
                        'loaded into (omit the slot to leave it symbolic). '
                        'Repeat for more callees.')
    g.add_argument('-c', '--constraints', metavar='JSON',
                   help='constraint JSON file (required for verification)')


def _add_output_args(g) -> None:
    g.add_argument('-o', '--info-output', metavar='TXT',
                   help="program report file (default: stdout)")
    g.add_argument('-j', '--info-json', metavar='JSON',
                   help="the same report as JSON ('-' for stdout)")
    g.add_argument('--spec-init', metavar='JSON',
                   help='write a runnable spec skeleton for this program')
    g.add_argument('-r', '--result-output', metavar='FILE',
                   help="verification result file (default: stdout)")


def _add_analysis_args(g) -> None:
    g.add_argument('-s', '--stage', choices=STAGES, default='all',
                   help='which pipeline stages to report')
    g.add_argument('-b', '--block', metavar='N', type=int,
                   help='report only this CFG block, in detail')
    g.add_argument('--spec-blocks', metavar='LIST',
                   help='--spec-init: only these blocks (e.g. 4,59,82)')
    g.add_argument('--all-blocks', action='store_true',
                   help='include every block in the report, not just the summary')
    g.add_argument('--reach-report', action='store_true',
                   help='also report per-block reachability (dead-code detection)')
    g.add_argument('--no-pipeline', action='store_true',
                   help='witness: print only the flat block path, not the '
                        'per-stage match-action detail')
    g.add_argument('-v', '--verbose', action='store_true',
                   help='verbose output')


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG_NAME,
        description='Hornet — static analysis and verification of eBPF programs.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    for name, add in (('input', _add_input_args), ('output', _add_output_args),
                      ('analysis', _add_analysis_args)):
        add(p.add_argument_group(name))
    return p


def parse_args(argv: Optional[Sequence[str]] = None) -> Config:
    cfg = Config.from_args(build_parser().parse_args(argv))
    if not os.path.isfile(cfg.input):
        raise CliError(f'input object file not found: {cfg.input}')
    if cfg.stage == 'verify' and not cfg.constraints:
        raise CliError(f'-c/--constraints is required for stage {cfg.stage!r}')
    if cfg.constraints and not os.path.isfile(cfg.constraints):
        raise CliError(f'constraint file not found: {cfg.constraints}')
    cfg.tail = _parse_tails(cfg.tail)
    if cfg.spec_blocks:
        try:
            cfg.spec_blocks = [int(n) for n in cfg.spec_blocks.replace(',', ' ').split()]
        except ValueError:
            raise CliError(f'--spec-blocks takes block ids: {cfg.spec_blocks!r}')
    return cfg


def _parse_tails(specs: Optional[Sequence[str]]) -> list:
    if not specs:
        return []
    from bpf.link import LinkError, parse_tail_spec
    out = []
    for text in specs:
        try:
            spec = parse_tail_spec(text)
        except LinkError as e:
            raise CliError(str(e))
        if not os.path.isfile(spec.path):
            raise CliError(f'--tail object file not found: {spec.path}')
        out.append(spec)
    return out


@contextlib.contextmanager
def _open_out(path: Optional[str]):
    if path in (None, '-'):
        yield sys.stdout
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            yield fh
    except OSError as e:
        raise CliError(f'cannot write {path}: {e}')


def run(cfg: Config) -> int:
    from program import eBPFProgram

    cfg.log(f'analyzing {cfg.input} (entry: {cfg.entry})')
    for spec in cfg.tail or ():
        cfg.log(f'  tail call target: {spec}')
    prog = eBPFProgram(cfg.input, main_func=cfg.entry, verbose=cfg.verbose >= 2,
                       tails=cfg.tail or ()).analyze()

    if cfg.run_info and cfg.spec_init != '-':
        try:
            text = (prog.block_report(cfg.block) if cfg.block is not None
                    else prog.report(blocks=cfg.all_blocks))
        except ValueError as e:
            raise CliError(str(e))
        with _open_out(cfg.info_output) as out:
            print(text, file=out)
        if cfg.info_json:
            with _open_out(cfg.info_json) as out:
                json.dump(prog.report_json(), out, indent=2, ensure_ascii=False)
                out.write('\n')
            cfg.log(f'report JSON written to {cfg.info_json}')

    if cfg.spec_init:
        blocks = cfg.spec_blocks if cfg.spec_blocks else None
        with _open_out(cfg.spec_init) as out:
            json.dump(prog.spec_scaffold(blocks=blocks), out, indent=2,
                      ensure_ascii=False)
            out.write('\n')
        if cfg.spec_init != '-':
            tails = ''.join(f' {t.as_flag()}' for t in cfg.tail or ())
            print(f'spec skeleton written to {cfg.spec_init} — '
                  f'it runs as-is:\n'
                  f'  {PROG_NAME} -i {cfg.input} -e {cfg.entry}{tails} '
                  f'-c {cfg.spec_init} -s verify', file=sys.stderr)

    if cfg.run_verify and cfg.constraints:
        cfg.log(f'verifying against {cfg.constraints}')
        with _open_out(cfg.result_output) as out, contextlib.redirect_stdout(out):
            results = prog.check(cfg.constraints, reach_all=cfg.reach_report,
                                 pipeline=not cfg.no_pipeline)
        violated = [r.name for r in results.violations]
        if violated:
            print(f"{len(violated)} violation(s): {', '.join(violated)}",
                  file=sys.stderr)
            return EXIT_VIOLATION
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    verbose = 0
    try:
        cfg = parse_args(argv)
        verbose = cfg.verbose
        return run(cfg)
    except CliError as e:
        print(f'{PROG_NAME}: error: {e}', file=sys.stderr)
        return EXIT_USAGE
    except Exception as e:
        if verbose:
            raise
        print(f'{PROG_NAME}: {type(e).__name__}: {e}', file=sys.stderr)
        return EXIT_ERROR


if __name__ == '__main__':
    sys.exit(main())
