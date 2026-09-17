import contextlib
import io
import os
import signal
import sys
import tempfile
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
import common

EXIT_RAISE, EXIT_NO_EXIT, EXIT_UNDETERMINED, EXIT_HORNET_EXIT, EXIT_TIMEOUT = 2, 3, 4, 5, 6
TIMEOUT = int(os.environ.get('HORNET_CONFORMANCE_TIMEOUT', '60'))
ETH_HLEN = 14


class _Timeout(BaseException):
    pass


def _base16(text: str) -> bytes:
    return bytes.fromhex(''.join(text.split()))


def _parse_args(argv):
    memory, elf = b'', False
    for arg in argv:
        if arg == '--elf':
            elf = True
        elif not arg.startswith('--'):
            memory = _base16(arg)
    return memory, elf


def _load_elf(code: bytes):
    fd, path = tempfile.mkstemp(suffix='.o')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(code)
        return common.track(path, 'main', tails=[])
    finally:
        os.unlink(path)


def _load_raw(code: bytes):
    from bpf.cfg import Cfg_builder
    from bpf.instr import Instr
    from bpf.link import ProgRegion
    from track.record import build_call_index
    from track.tracker import Tracker

    instrs, addr = [], 0
    while code:
        size = 16 if code[0] == 0x18 else 8
        instrs.append(Instr(idx=len(instrs), addr=addr, bytecode=code[:size]))
        code, addr = code[size:], addr + 8
        if size == 16:
            instrs.append(Instr(idx=len(instrs), addr=addr, nop=True))
            addr += 8
    progs = [ProgRegion(name='main', path='<raw>', start=0, end=len(instrs) - 1)]
    blocks, _, _ = Cfg_builder(instrs, progs, False).build_cfg()
    Tracker(blocks, instrs, [], progs, False).track(False)
    return SimpleNamespace(blocks=blocks, maps=[], calls=build_call_index(blocks))


def _entry_state(memory: bytes, maps):
    from verify.spec import InputSpec, z3_state_from_input
    data = memory.ljust(ETH_HLEN, b'\0')
    spec = InputSpec(pkt_bytes=dict(enumerate(data)), pkt_len=len(data),
                     map_values={})
    return z3_state_from_input(spec, maps)


def _return_values(prog, init_st):
    from z3 import And, BitVec, BoolVal, Or, Solver, sat
    from verify.forward import ForwardContext

    ctx = ForwardContext(prog.blocks, prog.maps, init_st=init_st,
                         calls=prog.calls)
    r0 = BitVec('conformance_r0', 64)
    arms = []
    for b, block in enumerate(prog.blocks):
        if not block.exit or block.ret_expr is None or b not in ctx.info:
            continue
        reach = ctx.reach(b)
        if reach is False:
            continue
        reach = BoolVal(True) if reach is True else reach
        arms.append(And(reach, r0 == ctx.ret_state(b).r0))
    if not arms:
        return None, None
    solver = Solver()
    solver.add(Or(arms))
    if solver.check() != sat:
        return None, None
    first = solver.model().eval(r0, model_completion=True).as_long()
    solver.add(r0 != first)
    if solver.check() != sat:
        return first, first
    return first, solver.model().eval(r0, model_completion=True).as_long()


def _fail(code: int, message: str) -> int:
    print(' '.join(message.split()), file=sys.stderr)
    return code


def main(argv) -> int:
    memory, elf = _parse_args(argv)
    code = _base16(sys.stdin.read())

    def on_alarm(signum, frame):
        raise _Timeout()
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(TIMEOUT)

    printed = io.StringIO()
    try:
        with contextlib.redirect_stdout(printed):
            prog = _load_elf(code) if elf else _load_raw(code)
            first, other = _return_values(prog, _entry_state(memory, prog.maps))
    except _Timeout:
        return _fail(EXIT_TIMEOUT, f'timeout after {TIMEOUT}s')
    except SystemExit as e:
        said = printed.getvalue().strip().splitlines()
        return _fail(EXIT_HORNET_EXIT,
                     f'hornet exited ({e.code}): {said[-1] if said else ""}')
    except Exception as e:
        return _fail(EXIT_RAISE, f'{type(e).__name__}: {e}')
    finally:
        signal.alarm(0)

    if first is None:
        return _fail(EXIT_NO_EXIT, 'no exit block is reachable')
    if other != first:
        return _fail(EXIT_UNDETERMINED,
                     f'r0 not determined by the input: {first:#x} or {other:#x}')
    print(f'{first:x}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
