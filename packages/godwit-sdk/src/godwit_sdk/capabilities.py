"""Capability declaration and enforcement: what a plugin says it needs, and the runtime check.

READ THE LIMITS BEFORE RELYING ON THIS
--------------------------------------
This is a **guardrail, not a sandbox**. It stops an honest plugin from doing something
its author forgot it was doing -- a debugging ``requests.get`` left in, a cache file
written to the working directory, a ``subprocess`` call in a helper library -- and it
makes those things fail loudly on the author's machine instead of silently inside a bank.
It does **not** contain a hostile plugin. In-process Python cannot: a plugin can reach
the interpreter through ``ctypes``, ``gc.get_objects()``, frame introspection or a C
extension, and any of those can turn the checks below off. A capability model inside one
Python process is a review aid with teeth. The containment boundary is a process.

So the recommendation is plain, and :attr:`godwit_sdk.PluginInfo.trust_category` states
it per plugin:

* ``ISOLATE`` -- every source plugin (it reads customer rows) and every plugin that
  declares any capability. If you did not write it and review it, run it in its own
  process, under its own OS user, with only the credentials and network routes it
  declared. A probe worker is already a separate process (``godwit-probe``'s
  ``WorkerPool``); run untrusted sources there, never in the orchestrator.
* ``IN_PROCESS`` -- a sketch, detector, feature, context source or panel that declares
  no capability. These are pure computations over values the SDK hands them. Reviewed
  code of this kind may run in-process; unreviewed code should still be isolated.

HOW ENFORCEMENT WORKS
---------------------
Every call from an SDK base class into plugin code runs inside a *plugin scope*. One
process-wide :func:`sys.addaudithook` hook, installed the first time a scope is entered,
inspects CPython audit events while a scope is active and refuses the undeclared ones:

=============  ==========================================================================
network        ``socket.getaddrinfo``, ``socket.connect``, ``http.client.connect``,
               ``urllib.Request`` and the other stdlib client events. Hosts are matched
               against the declared list (exact, or ``*.suffix``, or ``*`` for any).
filesystem     ``open`` and the ``os``/``shutil`` path events. Read-only opens of the
               interpreter's own files and of code on ``sys.path`` are always allowed,
               because importing a module opens files.
subprocess     ``subprocess.Popen``, ``os.system``, ``os.exec*``, ``os.spawn*``,
               ``os.posix_spawn``, ``os.fork``, ``os.startfile``.
always denied  ``_thread.start_new_thread`` (a new thread runs outside the scope, so
               allowing it would switch the checks off) and ``ctypes.dlopen`` (native
               code is outside anything this module can see).
=============  ==========================================================================

A refusal raises :class:`~godwit_sdk.errors.CapabilityViolationError` inside the plugin
*and* is recorded, so a plugin that catches the error and carries on still fails when
its call returns.

What it does not see: native code that opens sockets or files without going through
CPython's audit points (a C extension's own I/O), work done in threads or processes the
plugin did not start through Python, and anything done at *import* time, before the SDK
calls into the plugin. Import-time side effects are what the conformance kit's static
checks are for.

RESOURCE CEILINGS
-----------------
:class:`ResourceLimits` caps bytes handed over (sources), seconds and traced memory per
call. Seconds and memory are checked at audit events, between batches and when the call
returns: cooperative, so a plugin spinning in pure Python without touching I/O is only
stopped when it returns. Process isolation with an OS limit is the hard ceiling. The
clock read here decides only whether to stop; it never shapes a result, so determinism
(universal rule 5) is unaffected.
"""

from __future__ import annotations

import contextvars
import os
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from godwit_contracts.errors import BudgetExceededError
from godwit_source.errors import sanitise_driver_error

from godwit_sdk.errors import (
    CapabilityViolationError,
    PluginFailedError,
    ResourceLimitError,
    SdkError,
)

__all__ = ["Capabilities", "PluginRunner", "ResourceLimits"]


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What a plugin may do beyond computing. The default is nothing.

    ``network`` lists the hosts it may reach (``"api.example.com"``, ``"*.example.com"``,
    or ``"*"`` for any). ``filesystem`` lists the directories it may read and write.
    ``subprocess`` allows starting processes. Declare the narrowest thing that works:
    the declaration is shown to whoever installs the plugin.
    """

    network: tuple[str, ...] = ()
    filesystem: tuple[str, ...] = ()
    subprocess: bool = False

    @property
    def declared(self) -> bool:
        """True when the plugin asks for anything at all."""
        return bool(self.network or self.filesystem or self.subprocess)

    def describe(self) -> tuple[str, ...]:
        """One line per capability, for an installer to read. Hosts and paths are ours."""
        lines = [f"network: {host}" for host in self.network]
        lines += [f"filesystem: {path}" for path in self.filesystem]
        if self.subprocess:
            lines.append("subprocess")
        return tuple(lines)


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Per-plugin ceilings. ``None`` means no ceiling of that kind beyond the caller's.

    ``max_bytes_read`` applies to sources: Arrow bytes the plugin hands over in one probe.
    It is separate from, and composed with, the probe's ``CostBudget``. ``max_seconds``
    and ``max_memory_bytes`` apply to one call into the plugin (one probe, for a source).
    Memory is measured with :mod:`tracemalloc`, which slows the call; set it when you
    need it.
    """

    max_bytes_read: int | None = None
    max_seconds: float | None = None
    max_memory_bytes: int | None = None


_NETWORK_HOST_EVENTS: Final[dict[str, int]] = {
    "socket.getaddrinfo": 0,
    "socket.gethostbyname": 0,
    "socket.gethostbyname_ex": 0,
    "http.client.connect": 1,
    "ftplib.connect": 1,
    "smtplib.connect": 1,
    "poplib.connect": 1,
    "imaplib.open": 1,
    "nntplib.connect": 1,
}
"""Events whose argument at the given index is a host name."""

_NETWORK_ADDRESS_EVENTS: Final[frozenset[str]] = frozenset(
    {"socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind"}
)
_FILE_PATH_EVENTS: Final[dict[str, tuple[int, ...]]] = {
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.rmdir": (0,),
    "os.mkdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.link": (0, 1),
    "os.symlink": (0, 1),
    "os.truncate": (0,),
    "os.utime": (0,),
    "os.chdir": (0,),
    "shutil.rmtree": (0,),
    "shutil.copyfile": (0, 1),
    "shutil.copytree": (0, 1),
    "shutil.move": (0, 1),
    "shutil.make_archive": (0,),
}
_FILE_LISTING_EVENTS: Final[frozenset[str]] = frozenset({"os.listdir", "os.scandir", "glob.glob"})
_SUBPROCESS_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.startfile",
        "os.fork",
        "os.forkpty",
        "pty.spawn",
    }
)
_ALWAYS_DENIED: Final[dict[str, str]] = {
    "_thread.start_new_thread": "starting a thread (it would run outside the plugin scope)",
    "ctypes.dlopen": "loading native code",
}
_CODE_SUFFIXES: Final[tuple[str, ...]] = (".py", ".pyc", ".pyd", ".so", ".pyi", ".pth", ".dll")
_OPEN_FLAGS: Final[int] = 2
"""Index of ``flags`` in the ``open`` audit event's arguments."""
_WRITE_FLAGS: Final[int] = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _norm(path: object) -> str | None:
    """An absolute, case-normalised path, or None for a file descriptor."""
    if isinstance(path, int):
        return None
    if isinstance(path, bytes):
        path = os.fsdecode(path)
    if not isinstance(path, str | os.PathLike):
        return ""
    return os.path.normcase(os.path.normpath(Path(os.fspath(path)).absolute()))


def _within(path: str, roots: Iterable[str]) -> bool:
    for root in roots:
        if not root:
            continue
        base = os.path.normcase(os.path.normpath(Path(root).absolute()))
        if path == base or path.startswith(base.rstrip("\\/") + os.sep):
            return True
    return False


def _interpreter_roots() -> tuple[str, ...]:
    return tuple(dict.fromkeys((sys.prefix, sys.base_prefix, sys.exec_prefix)))


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    for declared in allowed:
        pattern = declared.lower()
        if pattern in ("*", host):
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
    return False


@dataclass(slots=True)
class _Scope:
    plugin: str
    capabilities: Capabilities
    limits: ResourceLimits
    deadline: float | None
    memory_ceiling: int | None
    violations: list[str] = field(default_factory=list)
    breaches: list[str] = field(default_factory=list)
    resolved_allowed_host: bool = False

    def judge(self, event: str, args: tuple[object, ...]) -> str | None:
        """A description of the violation, or None if the event is allowed."""
        if event in _ALWAYS_DENIED:
            return _ALWAYS_DENIED[event]
        if event in _SUBPROCESS_EVENTS:
            return None if self.capabilities.subprocess else "starting a process (subprocess)"
        if event in _NETWORK_HOST_EVENTS or event in _NETWORK_ADDRESS_EVENTS:
            return self._network(event, args)
        if event == "urllib.Request":
            host = (urlsplit(str(args[0])).hostname or "") if args else ""
            return self._host(host, resolved=False)
        if event == "open":
            return self._open(args)
        if event in _FILE_PATH_EVENTS:
            for index in _FILE_PATH_EVENTS[event]:
                path = _norm(args[index]) if len(args) > index else ""
                if path is not None and not _within(path, self.capabilities.filesystem):
                    return f"filesystem access ({event}) outside the declared directories"
            return None
        if event in _FILE_LISTING_EVENTS:
            path = _norm(args[0]) if args else ""
            if path is None or _within(path, self.capabilities.filesystem):
                return None
            if _within(path, (*_interpreter_roots(), *sys.path)):
                return None
            return f"filesystem access ({event}) outside the declared directories"
        return None

    def _network(self, event: str, args: tuple[object, ...]) -> str | None:
        if not self.capabilities.network:
            return f"network access ({event}) without declaring network"
        if event in _NETWORK_HOST_EVENTS:
            index = _NETWORK_HOST_EVENTS[event]
            host = args[index] if len(args) > index else ""
            if isinstance(host, bytes):
                host = host.decode("ascii", "replace")
            return self._host(str(host), resolved=event.startswith("socket.gethost"))
        address = args[1] if len(args) > 1 else None
        host = address[0] if isinstance(address, tuple) and address else address
        if isinstance(host, str) and _host_allowed(host, self.capabilities.network):
            return None
        if self.resolved_allowed_host:
            return None
        return f"network access ({event}) to a host that is not declared"

    def _host(self, host: str, *, resolved: bool) -> str | None:
        del resolved
        if not self.capabilities.network:
            return "network access without declaring network"
        if _host_allowed(host, self.capabilities.network):
            self.resolved_allowed_host = True
            return None
        return "network access to a host that is not declared"

    def _open(self, args: tuple[object, ...]) -> str | None:
        path = _norm(args[0]) if args else ""
        if path is None:
            return None
        mode = args[1] if len(args) > 1 else None
        flags = args[_OPEN_FLAGS] if len(args) > _OPEN_FLAGS else 0
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            mode is None and isinstance(flags, int) and bool(flags & _WRITE_FLAGS)
        )
        if _within(path, self.capabilities.filesystem):
            return None
        if not writing:
            if _within(path, _interpreter_roots()):
                return None
            if path.endswith(_CODE_SUFFIXES) and _within(path, sys.path):
                return None
        verb = "writing" if writing else "reading"
        return f"filesystem access ({verb} a file) outside the declared directories"

    def check_limits(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            self.breaches.append(f"exceeded max_seconds={self.limits.max_seconds}")
        if self.memory_ceiling is not None and tracemalloc.is_tracing():
            peak = tracemalloc.get_traced_memory()[1]
            if peak > self.memory_ceiling:
                self.breaches.append(f"exceeded max_memory_bytes={self.limits.max_memory_bytes}")


_ACTIVE: Final[contextvars.ContextVar[_Scope | None]] = contextvars.ContextVar(
    "godwit_sdk_plugin_scope", default=None
)
_HOOK_STATE: Final[dict[str, bool]] = {"installed": False}
_HOOK_LOCK: Final[threading.Lock] = threading.Lock()


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    scope = _ACTIVE.get()
    if scope is None:
        return
    # Judge with the scope switched off, so nothing the judgement itself does is audited.
    token = _ACTIVE.set(None)
    try:
        problem = scope.judge(event, args)
        if problem is None and scope.breaches == []:
            scope.check_limits()
            if scope.breaches:
                raise ResourceLimitError(f"plugin {scope.plugin} {scope.breaches[0]}")
    finally:
        _ACTIVE.reset(token)
    if problem is not None:
        scope.violations.append(problem)
        raise CapabilityViolationError(f"plugin {scope.plugin} attempted {problem}")


def _install_hook() -> None:
    with _HOOK_LOCK:
        if not _HOOK_STATE["installed"]:
            sys.addaudithook(_audit_hook)
            _HOOK_STATE["installed"] = True


def _advance[T](iterator: Iterator[T]) -> tuple[T] | None:
    """The next item wrapped in a 1-tuple, or None at the end."""
    for item in iterator:
        return (item,)
    return None


class PluginRunner:
    """Runs plugin code inside a scope, and defuses whatever it raises.

    Every SDK base class owns one, built from the plugin's declaration. Nothing a
    plugin raises leaves as itself: see :mod:`godwit_sdk.errors`.
    """

    __slots__ = ("capabilities", "limits", "plugin")

    def __init__(self, plugin: str, capabilities: Capabilities, limits: ResourceLimits) -> None:
        self.plugin = plugin
        self.capabilities = capabilities
        self.limits = limits

    def _open_scope(self, deadline: float | None) -> _Scope:
        _install_hook()
        ceiling = None
        if self.limits.max_memory_bytes is not None:
            if not tracemalloc.is_tracing():
                tracemalloc.start()
            tracemalloc.reset_peak()
            ceiling = tracemalloc.get_traced_memory()[0] + self.limits.max_memory_bytes
        return _Scope(
            plugin=self.plugin,
            capabilities=self.capabilities,
            limits=self.limits,
            deadline=deadline,
            memory_ceiling=ceiling,
        )

    def deadline(self) -> float | None:
        """The instant a call started now must finish by, or None."""
        if self.limits.max_seconds is None:
            return None
        return time.monotonic() + self.limits.max_seconds

    def call[T](self, stage: str, fn: Callable[[], T], *, deadline: float | None = None) -> T:
        """Run ``fn`` as plugin code. ``stage`` names the plugin method, for the error."""
        scope = self._open_scope(deadline if deadline is not None else self.deadline())
        token = _ACTIVE.set(scope)
        failure: BaseException | None = None
        result: list[T] = []
        try:
            result.append(fn())
        except Exception as exc:
            failure = exc
        finally:
            _ACTIVE.reset(token)
        if scope.violations:
            raise CapabilityViolationError(f"plugin {self.plugin} attempted {scope.violations[0]}")
        scope.check_limits()
        if scope.breaches:
            raise ResourceLimitError(f"plugin {self.plugin} {scope.breaches[0]}")
        if failure is not None:
            raise self._defuse(stage, failure)
        return result[0]

    def iterate[T](
        self, stage: str, factory: Callable[[], Iterable[T]], *, deadline: float | None = None
    ) -> Iterator[T]:
        """Iterate plugin-produced items, each ``next`` inside the scope."""
        until = deadline if deadline is not None else self.deadline()
        iterator = self.call(stage, lambda: iter(factory()), deadline=until)
        while (step := self.call(stage, lambda: _advance(iterator), deadline=until)) is not None:
            yield step[0]

    def _defuse(self, stage: str, exc: BaseException) -> SdkError:
        if isinstance(exc, BudgetExceededError):
            classification = "budget"
        else:
            classification = sanitise_driver_error(exc).classification
        return PluginFailedError(
            self.plugin,
            stage=stage,
            error_type=type(exc).__name__,
            classification=classification,
            original=sanitise_driver_error(exc).original,
        )
