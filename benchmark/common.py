import contextlib
import io
import os
import sys

BENCH = os.path.dirname(os.path.abspath(__file__))
ROOT  = os.path.dirname(BENCH)
PKG   = os.path.join(ROOT, 'hornet')
OBJS  = os.path.join(ROOT, 'example')
SPECS = os.path.join(BENCH, 'specs')

if PKG not in sys.path:
    sys.path.insert(0, PKG)


ENTRY = {
    'dhcp_kern_xdp':      'xdp_dhcp_relay',
    'xdp_cpumap_qinq':    'xdp_cpumap_qinq',
    'lb_kern':            'xdp_prog_simple',
    'xdp_bpfel':          'xdp_prog',
    'redirect_userspace': 'xdp_prog_redirect_userspace',
    'xdp_fw_kern':        'xdp_fw_prog',
    'balancer_main':      'balancer_ingress',
    'xdpfilt_alw_eth':    'xdpfilt_alw_eth',
    'xdpfilt_dny_eth':    'xdpfilt_dny_eth',
    'tailcall00_cb':      'xdp_tail_callee',
}

DEFAULT_ENTRY = 'xdp_prog_main'

KNOWN_TRACK_FAILURES = set()


def entry_of(stem: str) -> str:
    return ENTRY.get(stem, DEFAULT_ENTRY)


def is_xdp_section(name: str) -> bool:
    return name == 'prog' or name == 'xdp' or name.startswith(('xdp/', 'xdp.', 'xdp_'))


def xdp_entries(obj_path: str):
    from elftools.elf.elffile import ELFFile
    out = []
    with open(obj_path, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            return out
        for sym in symtab.iter_symbols():
            shndx = sym['st_shndx']
            if (sym['st_info']['type'] != 'STT_FUNC'
                    or sym['st_info']['bind'] != 'STB_GLOBAL'
                    or isinstance(shndx, str) or shndx == 0):
                continue
            sec = elf.get_section(shndx).name
            if is_xdp_section(sec):
                out.append((sec, sym.name))
    return out


# The E2 dataset: nine open-source XDP network functions, ordered by size.
# `source` is the project the object comes from; `obj` is relative to example/.
PROGRAMS = [
    ('fw',                 'hXDP',         'hxdp/xdp_fw_kern.o'),
    ('traffic-pacing-edt', 'bpf-examples', 'bpf-examples/xdp_cpumap_qinq.o'),
    ('hercules',           'Hercules',     'hercules/redirect_userspace.o'),
    ('fluvia',             'Fluvia',       'fluvia/xdp_bpfel.o'),
    ('xdp-filter-alw-eth', 'xdp-tools',    'xdp-tools/xdpfilt_alw_eth.o'),
    ('xdp-filter-dny-eth', 'xdp-tools',    'xdp-tools/xdpfilt_dny_eth.o'),
    ('crab',               'CRAB',         'crab/lb_kern.o'),
    ('dhcp-relay',         'bpf-examples', 'bpf-examples/dhcp_kern_xdp.o'),
    ('katran',             'Katran',       'katran/balancer_main.o'),
]

XDP_ACTIONS = {0: 'ABORTED', 1: 'DROP', 2: 'PASS', 3: 'TX', 4: 'REDIRECT'}


def object_path(rel: str) -> str:
    return os.path.join(OBJS, rel)


def cases(filt=None):
    out = []
    for group in sorted(os.listdir(SPECS)):
        gdir = os.path.join(SPECS, group)
        if not os.path.isdir(gdir):
            continue
        for f in sorted(os.listdir(gdir)):
            if not f.endswith('.json'):
                continue
            stem = f[:-5]
            rel = f'{group}/{stem}.o'
            out.append((f'{group}/{stem}', os.path.join(OBJS, rel),
                        entry_of(stem), os.path.join(gdir, f)))
    return [c for c in out if not filt or filt in c[0]]


def spec(group: str, name: str) -> str:
    return os.path.join(SPECS, group, name)


@contextlib.contextmanager
def quiet():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


def track(obj_path: str, entry: str, tails=None):
    from program import eBPFProgram
    p = eBPFProgram(obj_path, main_func=entry, verbose=False, tails=tails or [])
    p.decode_binary()
    p.build_cfg()
    p.track()
    return p


_CACHE = {}


def track_cached(obj_path: str, entry: str):
    key = (obj_path, entry)
    if key not in _CACHE:
        with quiet():
            _CACHE[key] = track(obj_path, entry)
    return _CACHE[key]
