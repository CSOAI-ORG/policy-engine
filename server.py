"""policy-engine-mcp — MEOK AI Labs.

Multi-language policy evaluation: Cedar (in-process via cedarpy) and
Rego (subprocess to ``opa`` binary, with graceful degradation when OPA
is not on PATH). Also includes policy validation and a line-based diff
that classifies added/removed permit/forbid rules.

Tools:
  - evaluate_cedar(policy, principal, action, resource, context="{}")
  - evaluate_rego(policy, input_json)            # needs `opa` on PATH
  - validate_cedar(policy, schema="")
  - policy_diff(policy_a, policy_b, kind="cedar")
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "policy-engine",
    instructions=(
        "Multi-language policy evaluation. evaluate_cedar runs Cedar in-process "
        "(requires pip install cedarpy). evaluate_rego shells out to the `opa` "
        "binary (install via `brew install opa` or the OPA releases page) — "
        "returns a graceful error if the binary is absent. validate_cedar "
        "checks syntax and type-correctness. policy_diff is a line-based diff "
        "that classifies added/removed permit/forbid rules."
    ),
)

_CEDAR_AVAILABLE: Optional[bool] = None
_CEDAR_VERSION: Optional[str] = None


def _cedar() -> Optional[dict]:
    """Lazily import cedarpy; return a dict describing availability."""
    global _CEDAR_AVAILABLE, _CEDAR_VERSION
    if _CEDAR_AVAILABLE is None:
        try:
            import cedarpy  # type: ignore  # noqa: F401
            _CEDAR_AVAILABLE = True
            _CEDAR_VERSION = getattr(cedarpy, "__version__", "unknown")
        except ImportError:
            _CEDAR_AVAILABLE = False
    return {"available": _CEDAR_AVAILABLE, "version": _CEDAR_VERSION}


# ---------- tool: evaluate_cedar ------------------------------------------


@mcp.tool(name="evaluate_cedar")
async def evaluate_cedar(
    policy: str,
    principal: str,
    action: str,
    resource: str,
    context: str = "{}",
) -> dict:
    """Evaluate a Cedar policy for a (principal, action, resource, context) tuple.

    ``policy``    : one or more Cedar ``permit(...)|forbid(...)`` statements
    ``principal`` : e.g. ``User::"alice"`` or ``Role::"admin"``
    ``action``    : e.g. ``Action::"view"``
    ``resource``  : e.g. ``Photo::"vacation"``
    ``context``   : JSON object as a string (default ``"{}"``)
    """
    avail = _cedar()
    if not avail["available"]:
        return {
            "error": "cedarpy not installed",
            "install": "pip install cedarpy",
        }
    try:
        import cedarpy  # type: ignore
        try:
            ctx = json.loads(context) if context.strip() else {}
        except json.JSONDecodeError as e:
            return {"error": f"context is not valid JSON: {e}"}
        result = cedarpy.is_authorized(
            policies={p.strip() for p in policy.splitlines() if p.strip()},
            entities=[],  # no entity store; principals/resources are inline
            principal=principal,
            action=action,
            resource=resource,
            context=ctx,
        )
        # cedarpy 4.x returns a RustDecision enum-like; .decision = "Allow"/"Deny"
        decision = getattr(result, "decision", None)
        if decision is None and isinstance(result, dict):
            decision = result.get("decision")
        if decision is None:
            decision = str(result)
        # Normalize Allow/Deny
        decision_str = str(decision)
        if hasattr(decision, "value"):
            decision_str = decision.value  # enum
        return {
            "decision": decision_str,
            "allowed": str(decision_str).lower() == "allow",
            "principal": principal,
            "action": action,
            "resource": resource,
        }
    except Exception as e:
        return {"error": f"cedar evaluation failed: {e}"}


# ---------- tool: validate_cedar -----------------------------------------


@mcp.tool(name="validate_cedar")
async def validate_cedar(policy: str, schema: str = "") -> dict:
    """Validate a Cedar policy's syntax (and optional schema).

    Returns ``{valid: bool, errors: [...]}``. ``schema`` is an optional
    Cedar schema string (Cedar 4.x ``entity User;`` style). If empty,
    syntax-only validation.
    """
    avail = _cedar()
    if not avail["available"]:
        return {
            "valid": False,
            "errors": [{
                "message": "cedarpy not installed",
                "install": "pip install cedarpy",
            }],
        }
    try:
        import cedarpy  # type: ignore
        try:
            result = cedarpy.validate_policies(
                policies={p for p in policy.splitlines() if p.strip()},
                schema=schema or None,
            )
            errors = []
            for err in (result.errors or []):
                errors.append({"message": str(err)})
            return {"valid": not errors, "errors": errors,
                    "cedarpy_version": avail["version"]}
        except AttributeError:
            # Older cedarpy: validate_policies not present — fall back to
            # a try/except around is_authorized with a sentinel request.
            try:
                cedarpy.is_authorized(
                    policies={p for p in policy.splitlines() if p.strip()},
                    entities=[],
                    principal='User::"__validate__"',
                    action='Action::"__validate__"',
                    resource='Resource::"__validate__"',
                    context={},
                )
                return {"valid": True, "errors": [], "note": "syntax-ok (fallback)"}
            except Exception as e:
                return {"valid": False, "errors": [{"message": str(e)}]}
    except Exception as e:
        return {"valid": False, "errors": [{"message": str(e)}]}


# ---------- tool: evaluate_rego ------------------------------------------


@mcp.tool(name="evaluate_rego")
async def evaluate_rego(policy: str, input_json: str) -> dict:
    """Evaluate a Rego policy by shelling out to the ``opa`` binary.

    Writes the policy to a temp file, pipes the input on stdin, runs
    ``opa eval --stdin-input -d <policy_path> 'data.example.allow'``.
    Returns ``{allow, result, stdout, stderr}`` or a graceful error if
    ``opa`` is not on PATH.
    """
    bin_path = shutil.which("opa")
    if bin_path is None:
        return {
            "error": "opa binary not installed. Install via: brew install opa",
            "fallback": "use evaluate_cedar",
        }
    try:
        parsed_input = json.loads(input_json)
    except json.JSONDecodeError as e:
        return {"error": f"input_json is not valid JSON: {e}"}
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".rego",
                                     delete=False) as f:
        f.write(policy)
        policy_path = f.name
    try:
        proc = subprocess.run(
            [bin_path, "eval", "--stdin-input",
             "-d", policy_path, "--format", "json", "data"],
            input=json.dumps(parsed_input).encode("utf-8"),
            capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"error": "opa eval timed out after 30s", "policy_path": policy_path}
    finally:
        try:
            os.unlink(policy_path)
        except OSError:
            pass
    if proc.returncode != 0:
        return {
            "error": "opa eval failed",
            "stderr": proc.stderr.decode("utf-8", "replace")[:4000],
            "returncode": proc.returncode,
        }
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "opa returned non-JSON", "raw": proc.stdout.decode(
            "utf-8", "replace")[:4000]}
    return {
        "result": result.get("result", {}),
        "stdout_excerpt": proc.stdout.decode("utf-8", "replace")[:2000],
    }


# ---------- tool: policy_diff --------------------------------------------


_PERMIT = re.compile(r"\b(permit|forbid)\b", re.IGNORECASE)
_EFFECT_RE = re.compile(r"^\s*(permit|forbid)\b", re.IGNORECASE)


def _classify_lines(text: str) -> Dict[str, List[str]]:
    """Split a policy into 'effect-bearing' lines and 'context' lines."""
    effects: List[str] = []
    context: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        if _EFFECT_RE.match(s):
            effects.append(s)
        else:
            context.append(s)
    return {"effects": effects, "context": context}


@mcp.tool(name="policy_diff")
async def policy_diff(policy_a: str, policy_b: str, kind: str = "cedar") -> dict:
    """Diff two policies; classify added/removed rules by effect (permit/forbid).

    ``kind`` is informational (e.g. ``"cedar"`` or ``"rego"``) and appears
    in the response. Diff is line-based — sufficient for human review
    before merging two policy versions.
    """
    if kind.lower() not in {"cedar", "rego", "general"}:
        return {"error": f"unknown kind: {kind!r}", "hint": "cedar|rego|general"}
    a = _classify_lines(policy_a)
    b = _classify_lines(policy_b)
    added_effects = sorted(set(b["effects"]) - set(a["effects"]))
    removed_effects = sorted(set(a["effects"]) - set(b["effects"]))
    added_context = sorted(set(b["context"]) - set(a["context"]))
    removed_context = sorted(set(a["context"]) - set(b["context"]))
    added_permits = [r for r in added_effects if r.lower().startswith("permit")]
    added_forbids = [r for r in added_effects if r.lower().startswith("forbid")]
    removed_permits = [r for r in removed_effects if r.lower().startswith("permit")]
    removed_forbids = [r for r in removed_effects if r.lower().startswith("forbid")]
    unified = list(difflib.unified_diff(
        policy_a.splitlines(), policy_b.splitlines(),
        fromfile="policy_a", tofile="policy_b", lineterm=""))
    return {
        "kind": kind,
        "added_permits": added_permits,
        "added_forbids": added_forbids,
        "removed_permits": removed_permits,
        "removed_forbids": removed_forbids,
        "added_context": added_context,
        "removed_context": removed_context,
        "unified_diff": "\n".join(unified)[:50_000],
    }


# ---------- entry point -------------------------------------------------


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
