import os as _os
import sys as _sys

_HERE = _os.path.dirname(_os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

__all__ = ['eBPFProgram', 'Verification']


def __getattr__(name):
    if name in __all__:
        import program
        return getattr(program, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
