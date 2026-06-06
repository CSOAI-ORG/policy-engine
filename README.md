# policy-engine-mcp

> MCP server for **multi-language policy evaluation** — Cedar (in-process via `cedarpy`) and Rego (subprocess to the `opa` binary, with graceful degradation when OPA is not on `PATH`). Includes policy validation and a line-based diff that classifies added/removed `permit`/`forbid` rules.

Part of the **MEOK AI Labs** security & compliance fleet, distributed via the
[MEOK Compliance Gateway](https://github.com/CSOAI-ORG/meok-compliance-gateway).

## Features

| Tool | Description |
|------|-------------|
| `evaluate_cedar` | Evaluate a Cedar policy for a `(principal, action, resource, context)` tuple. In-process, requires `pip install cedarpy`. |
| `evaluate_rego` | Evaluate a Rego policy by shelling out to the `opa` binary (`brew install opa`). Returns a graceful `{error, fallback}` response if the binary is absent. |
| `validate_cedar` | Validate a Cedar policy's syntax (and optional schema). Returns `{valid, errors}`. |
| `policy_diff` | Line-based diff of two policies; classifies added/removed `permit`/`forbid` rules and emits a unified-diff text. |

## Install

### PyPI

```bash
pip install policy-engine-mcp
# Optional, only needed for evaluate_cedar / validate_cedar
pip install cedarpy
# Optional, only needed for evaluate_rego
brew install opa   # or grab from https://www.openpolicyagent.org/docs/latest/#1-download-opa
python -c "import server; print(server.mcp)"
```

### Smithery

```bash
npx @smithery/cli install @nicholastempleman/policy-engine
```

### Container

```bash
docker pull ghcr.io/csoai-org/policy-engine-mcp:latest
docker run --rm -i ghcr.io/csoai-org/policy-engine-mcp:latest
```

## Use with the MEOK Compliance Gateway

The gateway imports this server in-process (`from server import mcp`):

```yaml
# meok-compliance-gateway/requirements-gateway.txt
policy-engine-mcp==0.1.0
cedarpy>=4.0.0
```

## Ecosystem

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-1f2937)](https://meok.ai)
[![PyPI](https://img.shields.io/pypi/v/policy-engine-mcp)](https://pypi.org/project/policy-engine-mcp/)
[![GHCR](https://img.shields.io/badge/GHCR-policy--engine--mcp-2496ed)](https://ghcr.io/csoai-org/policy-engine-mcp)
[![Smithery](https://img.shields.io/badge/Smithery-policy--engine--mcp-4f46e5)](https://smithery.ai/server/policy-engine-mcp)

## License

Apache-2.0 — see [LICENSE](LICENSE).
