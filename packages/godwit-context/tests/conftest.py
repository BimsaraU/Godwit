"""Puts this directory on ``sys.path`` so tests can share ``_context_support``.

The workspace runs pytest in importlib mode, where a test module cannot import a sibling
directly; conftest is imported first, so adding the path here is enough.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
