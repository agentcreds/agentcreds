"""The shipped type stub must describe the module it ships with.

`agentcreds.pyi` is hand-maintained, so it drifts silently: adding a `#[pymethods]` entry
in Rust does not touch it, and nothing fails. On 2026-07-31 it was missing **12 whole
classes** - `Gate`, `ApprovalEvidence`, `ConsumedApprovals`, `ApproverDirectory`,
`ApproverEntry`, `HumanAuthorization`, `HumanIdentity`, `VerifiedHumanPrincipal`,
`OidcProvider` and three exceptions - plus ~25 methods. That is the entire WIMSE R5/R6/R10
surface: principal binding, dual-axis authorization and execution-time human approval were
invisible to every type-checked consumer of the public SDK. The features shipped; the
ability to discover them did not.

The stub is read from the **installed package** (maturin ships it as
`agentcreds/__init__.pyi`), not from a path relative to this file, so the check tests what
users actually receive rather than what is in the tree.

Deliberately shallow: it checks that every public class and method is *declared*, not that
signatures match. A missing name is the failure that has actually happened; policing
parameter types here would fight PyO3's own signature rendering for little gain.
"""

import importlib.resources
import re

import agentcreds as ac
import pytest

# Names that exist on the module but are not part of the documented surface.
_NOT_API = {"__version__"}


def _stub_source() -> str:
    stub = importlib.resources.files("agentcreds").joinpath("__init__.pyi")
    if not stub.is_file():
        pytest.skip("installed agentcreds ships no __init__.pyi")
    return stub.read_text(encoding="utf-8")


def _public_classes() -> "list[str]":
    return sorted(
        n
        for n in dir(ac)
        if n[0].isupper() and n not in _NOT_API and isinstance(getattr(ac, n), type)
    )


def test_every_public_class_is_declared():
    stub = _stub_source()
    declared = set(re.findall(r"^class (\w+)", stub, re.M))
    missing = [c for c in _public_classes() if c not in declared]
    assert not missing, (
        "agentcreds.pyi does not declare: "
        + ", ".join(missing)
        + " - type-checked consumers cannot see these"
    )


def test_no_class_is_declared_that_does_not_exist():
    # The other direction: a stub that promises a class the module dropped is worse than
    # silence, because it type-checks and then fails at import.
    stub = _stub_source()
    declared = set(re.findall(r"^class (\w+)", stub, re.M))
    real = {n for n in dir(ac) if isinstance(getattr(ac, n), type)}
    phantom = sorted(declared - real)
    assert not phantom, f"agentcreds.pyi declares classes the module does not export: {phantom}"


def test_every_public_method_is_declared():
    stub = _stub_source()
    # Split the stub into per-class bodies so a method declared on one class does not
    # satisfy a different class that is missing it.
    bodies = {
        m.group(1): m.group(0)
        for m in re.finditer(r"^class (\w+)\b.*?(?=^class |\Z)", stub, re.M | re.S)
    }
    gaps = {}
    for cls in _public_classes():
        obj = getattr(ac, cls)
        if issubclass(obj, Exception):
            continue  # exception classes are declared as one-liners with no members
        body = bodies.get(cls, "")
        # `def name(` covers methods; `name:` / `name(self)` covers properties, which
        # PyO3 exposes as descriptors and the stub renders under @property.
        declared = set(re.findall(r"def (\w+)", body)) | set(
            re.findall(r"^\s+(\w+)\s*:", body, re.M)
        )
        real = {m for m in dir(obj) if not m.startswith("_")}
        missing = sorted(real - declared)
        if missing:
            gaps[cls] = missing
    assert not gaps, "agentcreds.pyi is missing members: " + "; ".join(
        f"{c}: {', '.join(ms)}" for c, ms in sorted(gaps.items())
    )
