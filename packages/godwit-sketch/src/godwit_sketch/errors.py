"""Every error this package raises.

``godwit-sketch`` has no I/O beyond serialisation, so these are all representation or
law violations: a merge that would silently produce a wrong answer, or a payload this
build cannot read. Refusing loudly is always correct here. A sketch that merges two
incompatible summaries and returns a plausible number is the worst outcome in the
package, because nothing above L1 can detect it.
"""

from __future__ import annotations

__all__ = [
    "GodwitSketchError",
    "IncompatibleMergeError",
    "InsufficientEntropyError",
    "SketchDecodeError",
    "SketchRegistryError",
    "UnsupportedCodecError",
    "UnsupportedVersionError",
]


class GodwitSketchError(Exception):
    """Base for every error raised by godwit-sketch."""


class IncompatibleMergeError(GodwitSketchError):
    """Two sketches were merged whose construction parameters differ.

    Contract law 4 on ``Sketch``: merging two KLL sketches with different ``k`` silently
    is a wrong answer, which is worse than an error.
    """


class SketchDecodeError(GodwitSketchError):
    """A payload is malformed, truncated, or not a Godwit sketch container at all."""


class UnsupportedVersionError(SketchDecodeError):
    """The payload was written by a newer build than this one.

    An older reader must refuse rather than misread. Forward compatibility is not
    claimed anywhere in this package, so guessing at an unknown layout would be a
    silent corruption, not a best effort.
    """


class UnsupportedCodecError(SketchDecodeError):
    """No registered sketch class claims this codec identifier."""


class SketchRegistryError(GodwitSketchError):
    """A sketch class was registered without satisfying the registry's requirements."""


class InsufficientEntropyError(GodwitSketchError):
    """An OPAQUE (hashed-key) sketch was configured over an enumerable input space.

    Keyed hashing is not anonymisation when the input space is small: a hashed
    four-digit PIN, country code or date of birth is enumerable in seconds by anyone who
    obtains the key. Such a column must be bucketed or blinded, never hashed and called
    safe.
    """
