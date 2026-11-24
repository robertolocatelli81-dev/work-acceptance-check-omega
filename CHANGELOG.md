# Changelog

Versions up to 0.12.0 are described in their commit messages and in the README sections named after each profile
("Profile 1.4.12", "Profile 1.4.11 rules", ...).

## 0.12.1 (2026-11-24)

Corrections of 0.12.0; no reading of the profile changes, and no outcome of any vector (README, "Version 0.12.1").

- `tools/fetch_sources.py` no longer fetches from a live URL. The issuer's key file had changed at
  api.babyblueviper.com (SHA-256 301a3531... against the pinned 2a4eb3cc...), so a fresh clone verified 449/450 sources
  and exited 1, and 4 of 455 tests failed. The key file is rebuilt from `selftest-pass.json` at 274159c (MIT),
  byte-identical to the file of 2026-10-18 (`fonti/issuer_274159c/checker-keys-20261018.json`); the two FreeTSA
  certificates come from web.archive.org captures with their pinned SHA-256. Rows of `SOURCES.json` have two closed
  forms (anything else: exit 2); downloads are read up to 16 MiB. `--live` reports drift (exit 3) or a URL that cannot
  be downloaded (exit 4) and writes nothing.
- `tools/score.py` refuses an unknown flag, option or value, a repeated option, an argument without `=` and an unknown
  `--set` with exit 2 and the reason (0.12.0 ignored `criteria-noncharacters=report` and gave 129/129, exit 0).
  `war_verify.verify` raises `ValueError` on an unknown option key.
- `strict_json_loads` counts the nesting on the text before parsing, in constant memory: deeper than 64 is refused,
  deeper than 512 under `--criteria-limits readable`, with the same reason on every Python (0.12.0 relied on
  `RecursionError`: 2,000 nested arrays were refused on Python 3.9.25 and read on 3.14.8).
- Every file the command line reads (record, `--keys`, `--relying-party-keys`, `--tsa-roots`) is read up to 16 MiB,
  then refused.
- `compare` (`--vector`) no longer stops with `TypeError` when an expected code list holds a list.
- Tests and tools open text files with `encoding="utf-8"`; `tools/score.py` names files with `/`; `.gitattributes`
  `* -text`.
- CI on every push: Linux, macOS and Windows, Python 3.9 to 3.14, each with the openssl command line, without it and
  without `cryptography`; actions pinned by commit; the live URLs as an informative job (warnings, red only if the tool
  fails). `release.yml`: the source archives of a tag, SHA256SUMS checked on its own line, build provenance attested.
- README: the babyblueviper1 files are under the MIT licence (the README said they state none); `SECURITY.md` added.
