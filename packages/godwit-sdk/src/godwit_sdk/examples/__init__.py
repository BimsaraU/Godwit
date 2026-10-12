"""The three reference plugins, which double as the tutorial.

Not part of the compatibility promise: import them to learn from, copy them to start
from, but do not build on them. Each is registered as an entry point of ``godwit-sdk``
itself (see its ``pyproject.toml``), exactly as a third-party plugin would be.

* :mod:`~godwit_sdk.examples.rest_source` -- a source over a paginated REST API.
* :mod:`~godwit_sdk.examples.bloom` -- a Bloom-filter membership sketch, and why it is
  value-bearing.
* :mod:`~godwit_sdk.examples.benford` -- a Benford's-law detector over money columns.
"""
