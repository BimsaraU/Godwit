"""Two publishers' plugins under one name, for the registry tests. Imported by name."""

from __future__ import annotations

from _sdk_support import MemorySource
from godwit_sdk import source


@source(name="memory", namespace="acme", version="1.2.3", summary="test source")
class AcmeMemory(MemorySource):
    """acme.memory"""


@source(name="memory", namespace="globex", version="0.1.0")
class GlobexMemory(MemorySource):
    """globex.memory"""
