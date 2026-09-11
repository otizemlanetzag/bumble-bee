This directory contains various Python modules used to support servo
development.

# `servo`

servo-specific python code e.g. implementations of mach commands. This
is the canonical repository for this code.

# `tidy`

servo-tidy is used to check licenses, line lengths, whitespace, ruff on
Python files, lock file versions, and more.

# `wpt`
servo-wpt is a module with support scripts for running, importing,
exporting, updating manifests, and updating expectations for WPT tests.

# Bumble Bee Python package

A Rust/PyO3 Python extension is available under `python/Cargo.toml` and
`python/pyproject.toml`.

Build it from this directory with:

```bash
pip install maturin
maturin develop --release
```

Then:

```python
import bumble_bee

browser = bumble_bee.Browser(1280, 720)
browser.load("https://example.com")
browser.paint()
```

For a wheel, use `maturin build --release` and install the generated wheel
with pip.
