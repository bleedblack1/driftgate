# Releasing

## One-time setup

1. Create accounts on [TestPyPI](https://test.pypi.org/account/register/) and
   [PyPI](https://pypi.org/account/register/). They are separate registries
   with separate credentials.
2. Enable 2FA on both. PyPI requires it for new projects.
3. Create an API token on each (Account settings -> API tokens). Scope the
   first one to "entire account", because the project does not exist yet.
   After the first upload, replace it with a project-scoped token.

Tokens start with `pypi-`. Treat them as passwords: never commit them, and
prefer Trusted Publishing (below) once the repository exists.

## Release checklist

```bash
# 1. green suite
.venv/bin/pytest

# 2. bump the version in pyproject.toml and add a CHANGELOG entry

# 3. build
uv build --out-dir build-out

# 4. validate metadata and long description
uv run --with twine twine check build-out/*

# 5. verify the artifact actually works, from a clean environment
D=$(mktemp -d) && uv venv "$D/v" -q
uv pip install --python "$D/v/bin/python" build-out/driftgate-*.whl
(cd "$D" && "$D/v/bin/driftgate" demo -n 4)
```

Step 5 is not optional. A clean-install check on this project caught two
crashes (`demo` and `roles`) while the entire unit suite was green, because
both bugs only appeared with no config file present.

## Publish to TestPyPI first

```bash
uv publish --publish-url https://test.pypi.org/legacy/ build-out/*
```

Then install from it exactly as a user would. `--extra-index-url` matters:
TestPyPI does not mirror real dependencies, so typer and rich must come from
the real index.

```bash
D=$(mktemp -d) && uv venv "$D/v" -q
uv pip install --python "$D/v/bin/python" \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  driftgate
"$D/v/bin/driftgate" demo -n 4
```

Check the rendered page at https://test.pypi.org/project/driftgate/ -- the
README renders there exactly as it will on PyPI.

## Publish to PyPI

```bash
uv publish build-out/*
```

A released version is **permanent**. It cannot be edited or replaced, only
yanked, and a yanked version stays downloadable by exact pin. Get TestPyPI
right first.

## Trusted Publishing

Once the GitHub repository exists, prefer Trusted Publishing over long-lived
tokens: PyPI mints a short-lived credential for a specific workflow, so there
is no secret to leak. Configure it at
`https://pypi.org/manage/project/driftgate/settings/publishing/` and use the
included `.github/workflows/release.yml`, which needs no secrets at all.
