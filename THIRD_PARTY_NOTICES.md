# Third-party dependency inventory

Link2Vault does not vendor third-party source code in this repository. The
following packages are direct build, runtime, or development dependencies in
`pyproject.toml`; their transitive dependencies remain governed by their own
licenses and metadata.

| Dependency | Direct use | Declared version | Resolved version in `uv.lock` | License | Source |
| --- | --- | --- | --- | --- | --- |
| Hatchling | PEP 517 build backend | `==1.32.0` | Not lockfile-managed; exactly pinned | MIT | [pypa/hatch](https://github.com/pypa/hatch/tree/master/backend) |
| FastAPI | Runtime API framework | `>=0.115,<1` | 0.141.1 | MIT | [fastapi/fastapi](https://github.com/fastapi/fastapi) |
| pydantic-settings | Runtime configuration | `>=2.8,<3` | 2.15.0 | MIT | [pydantic/pydantic-settings](https://github.com/pydantic/pydantic-settings) |
| Uvicorn | Runtime ASGI server | `>=0.30,<1` | 0.52.3 | BSD-3-Clause | [Kludex/uvicorn](https://github.com/Kludex/uvicorn) |
| pytest | Development test runner | `>=8,<10` | 9.1.1 | MIT | [pytest-dev/pytest](https://github.com/pytest-dev/pytest) |
| PyYAML | Development YAML parser for contract tests | `>=6,<7` | 6.0.3 | MIT | [yaml/pyyaml](https://github.com/yaml/pyyaml) |
| Ruff | Development linting | `>=0.8,<1` | 0.16.3 | MIT | [astral-sh/ruff](https://github.com/astral-sh/ruff) |
| Starlette with `full` extra | Development HTTP test support | `>=1.3,<2` | 1.6.0 | BSD-3-Clause | [Kludex/starlette](https://github.com/Kludex/starlette) |

This inventory was verified against the locked package metadata on
2026-08-17. When direct dependencies or resolved versions change, update this
file in the same change and review the upstream license text before release.
