"""Download the third-party inputs this verifier is measured against (vectors, the profile README, a live record,
the issuer's key file, the FreeTSA certificates). They are not redistributed here: each is fetched from the commit or
URL listed in SOURCES.json and kept only if its SHA-256 matches. Any mismatch or download error stops with exit 1 and
writes nothing for that file.

  python3 tools/fetch_sources.py            # fetch what is missing, check everything
  python3 tools/fetch_sources.py --check    # check only, no network
"""
import hashlib
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv):
    if argv not in ([], ["--check"]):
        print(__doc__)
        return 64
    rows = json.load(open(os.path.join(ROOT, "SOURCES.json"), encoding="utf-8"))
    bad = 0
    for r in rows:
        dst = os.path.join(ROOT, r["path"])
        if os.path.exists(dst):
            data = open(dst, "rb").read()
        elif argv == ["--check"]:
            print("MISSING", r["path"])
            bad += 1
            continue
        else:
            try:
                with urllib.request.urlopen(r["url"], timeout=30) as resp:
                    data = resp.read()
            except Exception as e:  # noqa: BLE001 — any network failure is reported, never skipped
                print("ERROR", r["path"], type(e).__name__, e)
                bad += 1
                continue
        got = hashlib.sha256(data).hexdigest()
        if got != r["sha256"]:
            print("SHA256 MISMATCH", r["path"], got, "expected", r["sha256"], "(source changed: not used)")
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
