# The vendored engine

`engine/` is not this repository's code. It is a copy of the Sedna engine, and this
file is the record of *which* copy, so that "keep the tuning up to date" is a
checkable statement rather than an intention.

| | |
|---|---|
| Upstream | [`titagram/sedna`](https://github.com/titagram/sedna) |
| Revision | `316c44e07fbadb6c8304ab93f1376754b4e927ee` (`chore(tests): apply ruff formatting to test_semantic_llm`) |
| Revision date | 2026-09-14 |
| Vendored | 2026-09-29 |
| Contents | `src/sedna` (90 modules, 53 961 lines), `pyproject.toml`, `README.md` |
| Deliberately **not** vendored | `tests/` — its fixtures contain flag-shaped literals on purpose, because they test flag detection; see `docs/decisions.md` D7 |
| Never vendored | `raw_src/` — collected write-ups; see `SECURITY.md` |

At the time of writing the vendored tree is byte-identical to the production checkout
it was taken from, which is what `tools/check-engine-drift.sh` checks.

## Updating it

```bash
# from a checkout of the upstream repository, at the revision you want to ship
rsync -a --exclude '__pycache__' --exclude '*.pyc' \
      src/sedna/ /path/to/sedna-dsh/engine/src/sedna/
cp pyproject.toml README.md /path/to/sedna-dsh/engine/

# then, from this repository
tools/check-engine-drift.sh /path/to/the/upstream/checkout   # expect: no drift
tests/run-all.sh                                             # expect: all checks passed
```

Update the revision and date in the table above in the same commit. A vendored copy
whose provenance is not recorded is a fork nobody knows they are maintaining.
