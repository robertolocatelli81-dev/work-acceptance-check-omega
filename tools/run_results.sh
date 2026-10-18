#!/bin/sh
# Regenerate results/ (everything except the mutation battery, see tools/mutate.py). Run from the repo root.
set -e
PY="${PY:-python3}"
mkdir -p results
# defaults = profile 1.3 (27 vectors of 42b4ed0 + live record); each switch's other value; this verifier's 1.2.1 readings
env -u PYTHONPATH $PY -B tools/score.py --json results/score_default.json > results/score_default.txt
for o in key_id_source=envelope reference_time=covering-token accuracy=ignore accuracy=interval \
         key_id_agreement=require key_id_agreement=ignore key_rule=all-keys key_rule=refuse \
         independence_rule=stated-independent time_agreement=exact name_compare=normalized correspondence=strict \
         ed25519=rfc8032 unknown_fields=report; do
  env -u PYTHONPATH $PY -B tools/score.py --json "results/score_${o%%=*}_${o#*=}.json" "$o" > "results/score_${o%%=*}_${o#*=}.txt"
done
env -u PYTHONPATH $PY -B tools/score.py --json results/score_profile_1_2_1.json --profile 1.2.1 > results/score_profile_1_2_1.txt
env -u PYTHONPATH $PY -B tools/score.py --json results/score_set_1_2_1_profile_1_2_1.json --set 1.2.1 --profile 1.2.1 \
  > results/score_set_1_2_1_profile_1_2_1.txt
env -u PYTHONPATH $PY -B tools/score.py --json results/score_set_1_2_1_defaults.json --set 1.2.1 \
  > results/score_set_1_2_1_defaults.txt
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
