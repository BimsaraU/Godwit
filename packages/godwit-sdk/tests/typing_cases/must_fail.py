"""Lines mypy must reject. Each carries the error code it must produce.

Checked by ``tests/test_logger.py``, which runs mypy over this file. Not collected by
pytest (no ``test_`` prefix) and excluded from the workspace mypy run (under tests/).
"""

from __future__ import annotations

from godwit_contracts import Acquisition, data_value
from godwit_sdk import PluginLogger

log = PluginLogger("acme.typing")
name = "Aoife Brennan"
row = {"customer_ssn": "100-40-1000"}
secret = data_value(name, acquisition=Acquisition.USER_SUPPLIED)

# mypy treats LiteralString as str, so it does NOT reject an f-string event (pyright
# does). The runtime check on the event's shape is what stops one under mypy; see log.py.
log.info(f"read {name}")
log.info("read", who=name)  # EXPECT: arg-type
log.info("read", row=row)  # EXPECT: arg-type
log.info("read", who=secret.reveal())  # EXPECT: arg-type
log.info("read", rows=len(row), who=secret)
