# Security policy

Please report vulnerabilities **privately**, not in a public issue or pull request: use GitHub's "Report a
vulnerability" button on the Security tab of this repository (private vulnerability reporting).

Useful in a report: the file and function, a record, vector, key file or command line that shows the problem, what you
expected and what happened, and the commit or release you tested.

In scope: a record that `war_verify.py` accepts as stated, or lets through to exit 0, when the profile or this README
says it must not (or the reverse); a member, option or input that is ignored instead of refused (see "Closed by
construction" in the README); a crash, hang or unbounded memory on any input; a signature or time-stamp check that
can be bypassed; a third-party input used without its pinned SHA-256 (`tools/fetch_sources.py`).

There is no bug bounty.

Supported versions: the latest release (see `CHANGELOG.md`) and the latest commit of the default branch.

Platforms the CI tests (`.github/workflows/ci.yml`, run on every push): Linux (`ubuntu-latest`, `ubuntu-24.04` for
Python 3.9), macOS (`macos-latest`) and Windows (`windows-latest`), each with Python 3.9 to 3.14, each with the openssl
command line, without it, and without `cryptography`. Other systems are not tested.
