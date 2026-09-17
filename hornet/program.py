from __future__ import annotations

import dataclasses
import os
import sys
import time

from bpf.loader import Loader
from bpf.link import link as _link, parse_tail_spec
from bpf.cfg import Cfg_builder
from track.tracker import Tracker
from track.record import build_call_index as _build_call_index


class Verification(list):

    def __init__(self, results=(), spec=None, elapsed: float = 0.0):
        super().__init__(results)
        self.spec    = spec
        self.elapsed = elapsed

    @property
    def verdicts(self) -> dict:
        return {r.name: r.verdict for r in self}

    @property
    def violations(self) -> list:
        return [r for r in self if r.verdict == 'violated']

    @property
    def ok(self) -> bool:
        return not self.violations

    def result(self, name: str):
        for r in self:
            if r.name == name:
                return r
        raise KeyError(name)

    def render(self, show_witness: bool = True, pipeline: bool = True) -> str:
        from verify.checker import render
        return render(self, show_witness=show_witness, pipeline=pipeline)


class eBPFProgram:
    def __init__(self, file_path: str, main_func: str = "xdp_prog_simple",
                 verbose: bool = False, tails=()):
        self.file_path = file_path
        self.main_func = main_func
        self.verbose   = verbose
        self.tails     = [parse_tail_spec(t) if isinstance(t, str) else t
                          for t in tails]
        self.progs     = []

        self.instrs  = []
        self.maps    = []
        self.blocks  = []
        self.rodata  = {}
        self.bss     = {}

        self.var_num       = 0
        self.sources         = []
        self.calls           = {}
        self.timings         = {}
        self._facts          = None

        self.loader  = Loader(file_path, main_func, verbose)
        self.loaders = [Loader(t.path, t.entry, verbose) for t in self.tails]
        self.cfg_builder = None
        self.tracker = None

    @classmethod
    def load(cls, file_path: str, entry: str = "xdp_prog_simple", tails=(),
             verbose: bool = False) -> 'eBPFProgram':
        return cls(file_path, main_func=entry, verbose=verbose,
                   tails=tails).analyze()


    STAGES = ('decode', 'cfg', 'track')

    def _done(self, stage: str, t0: float) -> None:
        for later in self.STAGES[self.STAGES.index(stage) + 1:]:
            self.timings.pop(later, None)
        self.timings[stage] = time.perf_counter() - t0

    def decode_binary(self) -> None:
        t0 = time.perf_counter()
        loads  = [self.loader.decode_binary()] + [l.decode_binary()
                                                  for l in self.loaders]
        result = _link(loads, self.tails)
        self.instrs = result['instrs']
        self.maps   = result['maps']
        self.rodata = result['rodata']
        self.bss    = result['bss']
        self.progs  = result['progs']
        self._done('decode', t0)

    def build_cfg(self) -> None:
        t0 = time.perf_counter()
        self.cfg_builder = Cfg_builder(self.instrs, self.progs, self.verbose)
        self.blocks, _, _ = self.cfg_builder.build_cfg()
        self._done('cfg', t0)

    def track(self, brief: bool = False) -> None:
        t0 = time.perf_counter()
        self.tracker = Tracker(self.blocks, self.instrs, self.maps, self.progs,
                               self.verbose, rodata=self.rodata)
        var_num, sources = self.tracker.track(brief)
        if not brief:
            self.var_num = var_num
            self.sources = sources
            self.calls   = _build_call_index(self.blocks)
            self._facts  = None
            self._done('track', t0)

    def analyze(self) -> 'eBPFProgram':
        if 'decode' not in self.timings:
            self.decode_binary()
        if 'cfg' not in self.timings:
            self.build_cfg()
        if 'track' not in self.timings:
            self.track()
        return self

    @property
    def tracked(self) -> bool:
        return 'track' in self.timings


    def exit_blocks(self) -> list[int]:
        from verify.prune import exit_blocks
        return exit_blocks(self.analyze().blocks)

    def stats(self) -> dict:
        self.analyze()
        return {
            'instrs':   len(self.instrs),
            'blocks':   len(self.blocks),
            'edges':    sum((b.succ_t is not None) + (b.succ_f is not None)
                            for b in self.blocks),
            'maps':     len(self.maps),
            'programs': max(1, len(self.progs)),
            'exits':    len(self.exit_blocks()),
            'sources':  len(self.sources),
            'vars':     self.var_num,
            'timings':  dict(self.timings),
        }


    def facts(self):
        if self._facts is None:
            from report.facts import ProgramFacts
            self._facts = ProgramFacts.collect(self.analyze())
        return self._facts

    def report(self, blocks: bool = False) -> str:
        from report.render import report as _report_text
        return _report_text(self.facts(), blocks=blocks)

    def block_report(self, num: int) -> str:
        from report.render import block_detail
        block = self.facts().block(num)
        if block is None:
            raise ValueError(f'no such block: {num} (0..{len(self.blocks) - 1})')
        return block_detail(block)

    def report_json(self, blocks: bool = True) -> dict:
        from report.render import to_json
        return to_json(self.facts(), blocks=blocks)

    def spec_scaffold(self, blocks=None) -> dict:
        from report.scaffold import spec_scaffold as _scaffold
        return _scaffold(self.facts(), blocks=blocks)


    def load_spec(self, spec):
        from verify.spec import Policy, load_spec, parse_spec
        if isinstance(spec, Policy):
            return spec
        self.analyze()
        against = dict(maps=self.maps, blocks=self.blocks, calls=self.calls)
        if isinstance(spec, dict):
            return parse_spec(spec, **against)
        return load_spec(os.fspath(spec), **against)

    def init_state(self, spec=None):
        if spec is None:
            return None
        policy = self.load_spec(spec)
        if policy.input is None:
            return None
        from verify.spec import z3_state_from_input
        return z3_state_from_input(policy.input, self.maps)

    def context(self, *specs, init_st=None, reach_all: bool = False):
        from verify.checker import context_for
        policies = [self.load_spec(s) for s in specs]
        if init_st is None:
            init_st = next((self.init_state(p) for p in policies if p.input),
                           None)
        self.analyze()
        return context_for(policies, self.blocks, self.maps, init_st=init_st,
                           calls=self.calls, reach_all=reach_all)

    def _whole_context(self, spec, init_st, ctx):
        if ctx is not None:
            return ctx
        return self.context(init_st=init_st if init_st is not None
                            else self.init_state(spec))


    def verify(self, spec, *, reach_all: bool = False, only=None, ctx=None,
               init_st=None) -> Verification:
        from verify.checker import check as _check
        policy = _select(self.load_spec(spec), only)
        if ctx is None and init_st is None:
            init_st = self.init_state(policy)
        t0 = time.perf_counter()
        results = _check(policy, self.blocks, self.maps, init_st=init_st,
                         calls=self.calls, reach_all=reach_all, ctx=ctx)
        return Verification(
            results, elapsed=time.perf_counter() - t0,
            spec=os.fspath(spec) if isinstance(spec, (str, os.PathLike)) else None)

    def check(self, spec, reach_all: bool = False, pipeline: bool = True,
              **kwargs) -> Verification:
        results = self.verify(spec, reach_all=reach_all, **kwargs)
        print(results.render(pipeline=pipeline))
        return results

    match = check


    def return_values(self, spec=None, *, values=range(5), ctx=None,
                      init_st=None) -> list[int]:
        from verify.checker import reachable_return_values
        self.analyze()
        if ctx is None and init_st is None:
            init_st = self.init_state(spec)
        return reachable_return_values(self.blocks, self.maps, init_st=init_st,
                                       values=values, ctx=ctx)

    def reachability(self, spec=None, *, ctx=None, init_st=None) -> list:
        from z3 import SolverFor
        from verify.checker import reach_report
        ctx = self._whole_context(spec, init_st, ctx)
        return reach_report(ctx, SolverFor('QF_ABV'))

    def dead_blocks(self, spec=None, *, ctx=None, init_st=None) -> list[int]:
        ctx = self._whole_context(spec, init_st, ctx)
        return [b for b, r in zip(sorted(ctx.info), self.reachability(ctx=ctx))
                if r.verdict == 'unsat']

    def query_cost(self, spec=None, *, ctx=None, init_st=None) -> dict:
        from verify.cost import query_cost
        ctx = self._whole_context(spec, init_st, ctx)
        return query_cost(ctx, self.blocks)


def _select(policy, only):
    if only is None:
        return policy
    names = {only} if isinstance(only, str) else set(only)
    known = set(policy.block_conditions) | set(policy.exit_conditions)
    if names - known:
        raise ValueError(f'no such condition(s) {sorted(names - known)} '
                         f'(spec has {sorted(known)})')
    return dataclasses.replace(
        policy,
        block_conditions={n: c for n, c in policy.block_conditions.items()
                          if n in names},
        exit_conditions={n: c for n, c in policy.exit_conditions.items()
                         if n in names})


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv:
        from cli import main as cli_main
        return cli_main(argv)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    obj  = os.path.join(root, 'example/katran/balancer_main.o')
    spec = os.path.join(root, 'benchmark/specs/katran/balancer_main.json')

    prog = eBPFProgram.load(obj, entry='balancer_ingress')
    print(prog.report())
    stages = '  '.join(f'{k} {v:.3f}s' for k, v in prog.timings.items())
    print(f"static analysis: {sum(prog.timings.values()):.6f}s  ({stages})")
    print("----------------------------------------------------")

    results = prog.check(spec)
    print(f"verification: {results.elapsed:.6f}s")
    return 0 if results.ok else 1


if __name__ == "__main__":
    sys.exit(main())
