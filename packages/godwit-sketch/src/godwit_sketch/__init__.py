"""Mergeable monoid sketches, and the time hierarchy that makes batch and streaming one thing.

Owner: A2. Layer: L1. **Plane: data.** This package reads values out of customer rows and
several of its outputs contain them, so treat everything it emits as something a bank's
security team will read line by line. ``docs/packages/godwit-sketch.md`` opens with the
disclosure table; the short version is:

===========================  ==============  ====================================
Class                        Value-bearing?  Why
===========================  ==============  ====================================
:class:`ThetaNdv`            no              stores hashes
:class:`HllCount`            no              stores register maxima
:class:`NullRate`            no              two counters
:class:`KllQuantile`         **yes**         retains sampled items, min and max
:class:`Moments`             **yes**         holds the minimum and the maximum
:class:`CountMinHeavy`       **yes**         heavy hitters are the keys themselves
:class:`CategoryHistogram`   **yes**         category labels are row values
:class:`GraphDegree`         **yes**         fan-in/fan-out hitters are identifiers
===========================  ==============  ====================================

Every value-bearing class exposes its stored state only as
:class:`~godwit_contracts.taint.Tainted`. There is no plain-string path to a key or an
extreme anywhere in the package, and ``tests/test_no_plain_value_path.py`` proves it by
inspecting the public API rather than by trusting the docs.

Three things here are worth knowing before you use it, and each is argued in full in the
module it belongs to:

* :mod:`godwit_sketch.quantile` implements KLL rather than wrapping the DataSketches
  one, because the upstream sketch is not deterministic and universal rule 5 forbids
  that.
* :mod:`godwit_sketch.base` explains why ``merge`` is exactly associative for five kinds
  and only associative-within-bound for three, and why no implementation can do better.
* :mod:`godwit_sketch.hierarchy` gets byte-identical batch and streaming results by
  folding in a canonical order, which does not depend on merge being order-free.
"""

from godwit_sketch.base import (
    SKETCH_REGISTRY,
    BaseSketch,
    ItemFlavour,
    MergeExactness,
    SketchContext,
    decode_envelope,
    register,
    registered_sketches,
)
from godwit_sketch.codec import payload_digest, producer_fingerprint
from godwit_sketch.distinct import (
    DEFAULT_THETA_SEED,
    ICEBERG_THETA_BLOB_TYPE,
    ThetaNdv,
)
from godwit_sketch.errors import (
    GodwitSketchError,
    IncompatibleMergeError,
    InsufficientEntropyError,
    SketchDecodeError,
    SketchRegistryError,
    UnsupportedCodecError,
    UnsupportedVersionError,
)
from godwit_sketch.features import (
    FEATURE_LAYOUT,
    FeatureSlot,
    extract_features,
    feature_index,
)
from godwit_sketch.frequency import CategoryHistogram, CountMinHeavy, HistogramRegime
from godwit_sketch.graph import Direction, GraphDegree
from godwit_sketch.hierarchy import Bucket, TimeHierarchy
from godwit_sketch.hll import HllCount
from godwit_sketch.items import MIN_OPAQUE_ENTROPY_BITS, KeyHasher, KeyMode
from godwit_sketch.moments import Moments, NullRate
from godwit_sketch.quantile import KllQuantile

__all__ = [
    "DEFAULT_THETA_SEED",
    "FEATURE_LAYOUT",
    "ICEBERG_THETA_BLOB_TYPE",
    "MIN_OPAQUE_ENTROPY_BITS",
    "SKETCH_REGISTRY",
    "BaseSketch",
    "Bucket",
    "CategoryHistogram",
    "CountMinHeavy",
    "Direction",
    "FeatureSlot",
    "GodwitSketchError",
    "GraphDegree",
    "HistogramRegime",
    "HllCount",
    "IncompatibleMergeError",
    "InsufficientEntropyError",
    "ItemFlavour",
    "KeyHasher",
    "KeyMode",
    "KllQuantile",
    "MergeExactness",
    "Moments",
    "NullRate",
    "SketchContext",
    "SketchDecodeError",
    "SketchRegistryError",
    "ThetaNdv",
    "TimeHierarchy",
    "UnsupportedCodecError",
    "UnsupportedVersionError",
    "__version__",
    "decode_envelope",
    "extract_features",
    "feature_index",
    "payload_digest",
    "producer_fingerprint",
    "register",
    "registered_sketches",
]

__version__ = "0.1.0"
