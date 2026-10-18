#!/bin/sh
# Regenerate results/ (everything except the mutation battery, see tools/mutate.py). Run from the repo root.
set -e
PY="${PY:-python3}"
mkdir -p results
env -u PYTHONPATH $PY -B tools/score.py --json results/score_default.json > results/score_default.txt
for o in reference_time=earlier key_id_source=receipt time_agreement=exact accuracy=interval name_compare=normalized \
         correspondence=strict ed25519=rfc8032 unknown_fields=report key_id_agreement=ignore; do
  env -u PYTHONPATH $PY -B tools/score.py --json "results/score_${o%%=*}_${o#*=}.json" "$o" > "results/score_${o%%=*}_${o#*=}.txt"
done
env -u PYTHONPATH $PY -B -c "
import sys, glob; sys.path.insert(0, 'tools'); sys.path.insert(0, '.')
import score, json
rows = score.score(files=sorted(glob.glob('vectors/*.json')))
json.dump(rows, open('results/score_new_vectors.json', 'w'), indent=1, sort_keys=True, default=str)
print('new vectors: %d/%d agree' % (sum(r['agree'] for r in rows), len(rows)))" > results/score_new_vectors.txt
env -u PYTHONPATH nice -n 10 $PY -B tools/fuzz.py --json results/fuzz.json > results/fuzz.txt
env -u PYTHONPATH $PY -B tools/ed25519_edges.py > results/ed25519_edges.txt
env -u PYTHONPATH $PY -B war_verify.py --vector --tokens pkix --tsa-roots roots/freetsa_cacert.pem \
  fonti/issuer_274159c/selftest-pass.json > results/selftest_pkix.json || true
env -u PYTHONPATH $PY -B tools/compose.py > results/compose.txt
