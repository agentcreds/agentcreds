"""Best-effort decision reporting to the control plane.

A relying party (e.g. an MCP server) enforces authority **offline** on the hot
path and never calls the control plane to decide a tool call. But operators still
want the control plane's console, its signed audit export, and its SIEM stream to
reflect what happened at the edge. :class:`DecisionReporter` bridges that gap: it
is an ``AdrSink`` (``Callable[[ac.AuthzDecision], None]``) that forwards each
Authorization Decision Record to the control plane's ``/decisions/report`` ingest
endpoint.

Design (mirrors the control plane's own SIEM posture): the live report is
**best-effort** - records are queued and shipped by a daemon thread; on a full
queue or any network error the record is dropped and a counter bumped. The
control plane's signed pull-export remains the authoritative backfill, so a
dropped report is never a correctness problem. Crucially, ``__call__`` never
blocks and never raises into the enforcement hot path.
"""

from __future__ import annotations

import queue
import threading
import urllib.request
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    import agentcreds as ac


class DecisionReporter:
    """Forward each ADR to the control plane's decision-ingest endpoint.

    Args:
        url: the ingest endpoint, e.g. ``https://console.example/decisions/report``.
        token: shared bearer token the control plane expects (``AC_DECISION_REPORT_TOKEN``);
            omit for an unauthenticated endpoint (not recommended).
        timeout: per-request timeout in seconds.
        queue_max: bounded backlog; reports are dropped (counted) when it is full.

    Use as the enforcer's ``adr_sink``::

        enforcer = IdentityEnforcer(anchor, config=PolicyConfig(adr_sink=DecisionReporter(url, token)))
    """

    def __init__(
        self,
        url: str,
        token: Optional[str] = None,
        *,
        timeout: float = 3.0,
        queue_max: int = 1000,
    ) -> None:
        self._url = url
        self._token = token
        self._timeout = timeout
        self._q: "queue.Queue[str]" = queue.Queue(maxsize=queue_max)
        self.forwarded = 0
        self.dropped = 0
        self.errors = 0
        self._thread = threading.Thread(
            target=self._run, name="agentcreds-decision-reporter", daemon=True
        )
        self._thread.start()

    def __call__(self, adr: "ac.AuthzDecision") -> None:
        """AdrSink entrypoint - enqueue the record; never blocks, never raises."""
        try:
            self._q.put_nowait(adr.to_json())
        except queue.Full:
            self.dropped += 1
        except Exception:  # noqa: BLE001 - reporting must never break enforcement
            self.dropped += 1

    def _run(self) -> None:
        while True:
            body = self._q.get()
            headers = {"Content-Type": "application/json"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            try:
                req = urllib.request.Request(
                    self._url, data=body.encode("utf-8"), headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                    resp.read()
                self.forwarded += 1
            except Exception:  # noqa: BLE001 - best-effort; drop on any error
                self.errors += 1
