"""The SDK's version, in its own module so every other module can import it without a cycle.

This number is the compatibility promise. See ``docs/packages/godwit-sdk.md`` section 2.
``tests/test_api_surface.py`` fails when a public symbol changes and this does not.
"""

from __future__ import annotations

from typing import Final

__all__ = ["__version__"]

__version__: Final[str] = "0.1.0"
