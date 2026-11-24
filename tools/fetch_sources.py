"""Download the third-party inputs this verifier is measured against (vectors, the profile README, a live record,
the issuer's key file, the FreeTSA certificates). They are not redistributed here: each is fetched from a dated copy
listed in SOURCES.json (a GitHub commit, or a web.archive.org capture with its time stamp) and kept only if its SHA-256
matches; the issuer's key file is rebuilt from the issuer's selftest-pass.json at a commit. No row is fetched from a
live URL: a file that its owner can change there would stop a fresh clone. Any mismatch or download error stops with
exit 1 and writes nothing for that file; a SOURCES.json row outside the two forms below is refused with exit 2.

  python3 tools/fetch_sources.py            # fetch what is missing, check everything
  python3 tools/fetch_sources.py --check    # check only, no network
  python3 tools/fetch_sources.py --live     # optional: download the live URLs and report drift from the pinned bytes
                                            # (exit 0 none, 3 drift, 4 a live URL not downloaded); writes nothing

Row forms (closed): {"path", "url", "sha256"} with url a dated copy, optionally "live_url"; {"path", "derived_from",
"live_url", "sha256"}, the key file rebuilt from the `inputs.keys` of derived_from.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_BYTES = 16 * 1024 * 1024        # no source is larger than 100 kB; a download past this is an error, never kept
# A dated copy: a file at a commit of a GitHub repository, or a web.archive.org capture fixed by its time stamp (id_ =
# the bytes as captured).
DATED = re.compile(r"\Ahttps://(raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/"
                   r"|web\.archive\.org/web/[0-9]{14}id_/https?://)[^\s]+\Z")
FETCHED, FETCHED_LIVE, DERIVED = {"path", "url", "sha256"}, {"path", "url", "sha256", "live_url"}, \
    {"path", "derived_from", "live_url", "sha256"}
# Member order of the key file served at the live URL when it was first fetched (2026-10-18, SHA-256 2a4eb3cc...):
# selftest-pass.json carries the same value with its members sorted, so the bytes are rebuilt in that order.
KEYFILE_ORDER = ("version", "issuer", "purpose", "keys", "also_published")
KEY_ORDER = ("key_id", "alg", "public_key_base64", "status", "since")


def row_error(r):
    """None for a row of one of the closed forms, else the reason."""
    if not isinstance(r, dict) or set(r) not in (FETCHED, FETCHED_LIVE, DERIVED):
        return "not one of the row forms: %r" % (sorted(r) if isinstance(r, dict) else type(r).__name__)
    if not all(isinstance(v, str) for v in r.values()):
        return "a member is not a string"
    if not re.fullmatch(r"[0-9a-f]{64}", r["sha256"]):
        return "sha256 is not 64 lower-case hex digits"
    for k in ("path", "derived_from"):
        if k in r and (not re.fullmatch(r"(fonti|roots)(/[A-Za-z0-9_.-]+)+", r[k]) or "/.." in r[k] or "/./" in r[k]):
            return "%s %r is not a plain path under fonti/ or roots/" % (k, r[k])
    if "url" in r and not DATED.match(r["url"]):
        return "url %r is not a dated copy (a commit or a web.archive.org capture)" % r["url"]
    if "live_url" in r and not re.fullmatch(r"https://[^\s]+", r["live_url"]):
        return "live_url is not an https URL"
    return None


def derive_keyfile(selftest):
    """The bytes of the issuer's key file, from the bytes of selftest-pass.json."""
    keys = json.loads(selftest.decode("utf-8"))["inputs"]["keys"]
    doc = {m: keys[m] for m in KEYFILE_ORDER}
    doc["keys"] = [{m: k[m] for m in KEY_ORDER} for k in keys["keys"]]
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def download(url, attempts=3):
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("more than %d bytes" % MAX_BYTES)
            return data
        except ValueError:
            raise
        except Exception:  # noqa: BLE001 — a network failure is retried, then reported by the caller
            if i == attempts - 1:
                raise
            time.sleep(5 * (i + 1))


def read_local(path):
    with open(path, "rb") as fh:
        data = fh.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("more than %d bytes" % MAX_BYTES)
    return data


def live(rows):
    drift = err = 0
    for r in rows:
        if "live_url" not in r:
            continue
        try:
            data = download(r["live_url"], attempts=1)
        except Exception as e:  # noqa: BLE001
            print("ERROR", r["live_url"], type(e).__name__, e)
            err += 1
            continue
        got = hashlib.sha256(data).hexdigest()
        if got == r["sha256"]:
            print("LIVE SAME", r["path"], r["live_url"])
        else:
            drift += 1
            print("LIVE DRIFT", r["path"], r["live_url"], "sha256", got, "pinned", r["sha256"],
                  "(the pinned bytes are still used; the live file is not)")
    print("%d live URL(s) drifted, %d not downloaded" % (drift, err))
    return 4 if err else (3 if drift else 0)        # 1 and 2 stay the tool's own failures


def main(argv):
    if argv not in ([], ["--check"], ["--live"]):
        print(__doc__)
        return 64
    try:
        rows = json.loads(read_local(os.path.join(ROOT, "SOURCES.json")).decode("utf-8"))
    except (OSError, ValueError) as e:
        print("SOURCES.json cannot be read:", type(e).__name__, e)
        return 2
    if not isinstance(rows, list):
        print("SOURCES.json is not a list")
        return 2
    for i, r in enumerate(rows):
        why = row_error(r)
        if why:
            print("SOURCES.json row %d refused: %s" % (i, why))
            return 2
    if argv == ["--live"]:
        return live(rows)
    bad = 0
    for r in sorted(rows, key=lambda r: "derived_from" in r):      # a derived file after the file it comes from
        dst = os.path.join(ROOT, r["path"])
        try:
            if os.path.exists(dst):
                data = read_local(dst)
            elif argv == ["--check"]:
                print("MISSING", r["path"])
                bad += 1
                continue
            elif "derived_from" in r:
                data = derive_keyfile(read_local(os.path.join(ROOT, r["derived_from"])))
            else:
                data = download(r["url"])
        except Exception as e:  # noqa: BLE001 — any failure is reported, never skipped
            print("ERROR", r["path"], type(e).__name__, e)
            bad += 1
            continue
        got = hashlib.sha256(data).hexdigest()
        if got != r["sha256"]:
            print("SHA256 MISMATCH", r["path"], got, "expected", r["sha256"], "(not used)")
            bad += 1
            continue
        if not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
        print("ok", r["path"])
    print(f"{len(rows) - bad}/{len(rows)} sources verified")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
