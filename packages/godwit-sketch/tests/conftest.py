"""Makes this directory importable so the suite can share one support module.

The workspace runs pytest with ``--import-mode=importlib`` (seventeen packages each ship
a ``tests/`` directory and the basenames collide, so prepend mode cannot import them).
Under importlib, a test module cannot simply ``import conftest``, and the shared
strategies in ``_support.py`` are needed at module scope -- they parametrise the law
suite, which happens at collection time, before any fixture could run.

conftest is imported before the test modules it sits beside, so putting the directory on
``sys.path`` here is enough to make ``from _support import ...`` work.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
