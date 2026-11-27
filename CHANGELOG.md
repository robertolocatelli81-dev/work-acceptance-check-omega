# Changelog

Versions up to 0.12.0 are described in their commit messages and in the README sections named after each profile
("Profile 1.4.12", "Profile 1.4.11 rules", ...).

## Unreleased (0.12.2)

A secret given by mistake does not come out; no reading of the profile changes, and no outcome of any vector (README,
"Unreleased: a secret given by mistake does not come out").

- war-verify reads public material only, so a secret enters only by mistake: a private key, a seed or a password put in
  a key file, a relying party's list, a record or a TSA root file. 0.12.1 repeated some of it in its reports: a member
  name or a `key_id` of any length (in a refusal, a note, `details.rejected_keys`), the value of a key entry's
  `status`, a member name of the criteria document, and one byte of a file that is not UTF-8 ("can't decode byte 0x..
  in position N"). Measured on the files of the 0.12.1 release (SHA256SUMS checked): 9 of the 13 tests of
  `tests/test_secrets_20261127.py` fail there (61 failures and 3 errors of subtests, on Python 3.9.25 and 3.13.15); in
  43 of the 92 pairs of a key-file shape and a channel the canary comes out (13 of the 23 shapes).
- Now a member name (of the record, a key file, a relying party's list or the criteria document), and a `key_id` or a
  `status` of a key file or a relying party's list, is repeated up to 32 characters, a longer one only by its length
  ("<a name of 43 characters>"; long `key_id`s shown alike stay separate entries of `rejected_keys`, and a short one
  spelled like a shown one overwrites none); a file that is not UTF-8 is named by the position of the first bad byte,
  not by the byte. The values the signed record states, its `key_id`s among them, are repeated as written.
- A `--tsa-roots` file holding a private key is refused as a check that cannot run (exit 74, "holds a private key
  (PEM)" for any `-----BEGIN ... PRIVATE KEY-----` or `PRIVATE KEY BLOCK-----` block, encrypted or not, "(DER)" for
  PKCS#8, encrypted PKCS#8, PKCS#1 or SEC1), with any version of `cryptography`; 0.12.1 read the certificates beside
  it and ignored the key.
- `tests/test_secrets_20261127.py`: a canary (an Ed25519 seed, a key put where a name goes, a password, an environment
  variable) in every input that takes a key, searched in standard output and error and in every file left, raw and in
  hex, HEX, decimal, base64 and base64url at each offset; an audit hook checks that the command line starts no process
  and opens no connection; the source reads no environment variable. Positive control: the search finds each form, and
  a producer that repeats names is caught.

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
  `--set`, and a flag given another flag as its value, with exit 2 and the reason (0.12.0 ignored `criteria-noncharacters=report` and gave 129/129, exit 0).
  `war_verify.verify` raises `ValueError` on an unknown option key.
- `strict_json_loads` counts the nesting on the text before parsing, in constant memory: deeper than 64 is refused,
  deeper than 512 under `--criteria-limits readable`, with the same reason on every Python (0.12.0 relied on
  `RecursionError`: 2,000 nested arrays were refused on Python 3.9.25 and read on 3.14.8). A caller deep in its own
  stack that still reaches Python's limit gets the refusal "JSON nesting too deep for the call stack".
- Every file the command line reads (record, `--keys`, `--relying-party-keys`, `--tsa-roots`) is read up to 16 MiB,
  then refused (exit 2; a `--tsa-roots` file past the bound is a check that cannot run, exit 74).
- `tools/search0121.py`: the search of the entry points behind these corrections (`verify`, `inputs`, `argv`).
- `compare` (`--vector`) no longer stops with `TypeError` when an expected code list holds a list.
- Tests and tools open text files with `encoding="utf-8"`; `tools/score.py` names files with `/`; `.gitattributes`
  `* -text`.
- CI on every push: Linux, macOS and Windows, Python 3.9 to 3.14, each with the openssl command line, without it and
  without `cryptography`; actions pinned by commit; the live URLs as an informative job (warnings, red only if the tool
  fails). `release.yml`: the source archives of a tag, SHA256SUMS checked on its own line, build provenance attested.
- README: the babyblueviper1 files are under the MIT licence (the README said they state none); `SECURITY.md` added.
