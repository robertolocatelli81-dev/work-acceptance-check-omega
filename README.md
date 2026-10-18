# war-verify: a clean-room verifier for work-acceptance records (profile 1.3)

`war_verify.py` checks a work-acceptance record (Trilatic draft profile 1.3 at
maximusrufus/work-acceptance-record@42b4ed0, schema identifier `trilatic.acceptance-receipt/1.2`, unchanged since
1.2.1) the way the profile README describes, and refuses anything it does not understand. The readings this
verifier gave to profile 1.2.1 (version 0.1.0) are kept: `--profile 1.2.1` selects all of them, and each one has
its own switch (see "Switches"). It was written from the profile README, the published test vectors and the RFCs it names, without
reading any other implementation (see "What was read").

Licence of this project's own files: MIT OR Apache-2.0 (`LICENSE-MIT`,
`LICENSE-APACHE`). The new vectors in `vectors/` are CC0, like the upstream vectors.

Third-party inputs are **not included** in this repository. `python3 tools/fetch_sources.py` downloads them from the
commits and URLs pinned in `SOURCES.json` into `fonti/` and `roots/`, and keeps a file only if its SHA-256 matches;
the tests need them. Their licences are their authors': the profile README is CC BY 4.0
(maximusrufus/work-acceptance-record), the upstream vectors (01-27 at 42b4ed0) and the Tetsurohhori vectors carry
CC0-1.0, and the babyblueviper1
vectors and the issuer files (`selftest-pass.json`, its README, `checker-keys-live.json`) state no licence. The
issuer's key file is fetched from its live URL, so it can change: the script then reports a mismatch and does not
use it.

## What it checks

Profile steps 1-9, with the problem and warning codes of step 8:

1. schema, canonicalization and suite are the ones of the profile, otherwise refusal with the outcome
   `{"refused": true, "reason": "unknown schema, canonicalization or suite"}`;
2. RFC 8785 canonical form of `receipt` (own implementation, tested on RFC 8785 Appendix B), Ed25519 signature with
   the key named by the signed `receipt.key_id`. An envelope `signature.key_id` that differs is `SIGNATURE_INVALID`.
   Key rule: if the key named by `receipt.key_id` is not a canonical encoding of a point of prime order, the
   record is `KEY_REJECTED` and no signature check runs (another bad entry in the key file gives the local block
   `X_UNUSED_KEY_REJECTED`, see `--key-rule`);
3. delivered and original files, when supplied (`delivered_file_base64`, `original_file_base64`);
4. criteria document hash, and that the results correspond to the criteria;
5. criteria commitment: imprint of the criteria token (SHA-256 by OID), its genTime against `committed_at`,
   fallback to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED`, strict "earlier than" against the reference
   time, which is the earlier of `issued_utc` and a covering record token's genTime. A token's stated `accuracy`
   widens the comparison, a token without one is taken at its genTime, and `ordering` is ignored;
6. record token imprint (`none` / `imprint_match` / `imprint_mismatch`); the unsigned `timestamp.digest_sha256`
   never decides it;
7. verdict recomputed from the results;
8. independence: checker is the signer, key collision, self-check label, producer declared, and the stated
   `independence` against the one derived from the parties block;
9. time-stamp authority signature: not part of the profile fields; `--tokens pkix` checks it and reports it
   separately (`details.token_authentication`).

The output has the nine fields of the vectors' `expected` objects, plus `accepted_as_stated`, `extension_codes`
(this verifier's own observations, prefixed `X_`, never mixed with the profile's codes), `notes` and `details`.

## What it does not check

- With the default `--tokens structural` it does not verify the time-stamp authority's signature. Profile 1.3 step 9:
  "The outcome fields cover imprint and time only"; the vectors' tokens are "imprint-and-time fixtures" with no
  SignerInfo. `--tokens pkix --tsa-roots ROOTS` adds the
  RFC 3161 checks (below).
- Revocation of TSA certificates (no CRL or OCSP is fetched).
- OpenTimestamps proofs. The issuer README says its criteria commitment comes with an OpenTimestamps proof, but
  `selftest-pass.json` contains no OpenTimestamps data, so there was nothing to check.
- Whether a criterion was judged correctly. A record states a checker's findings; this tool checks the record.

## Closed by construction

Every member of every object is either understood or the input is refused with a reason naming the path. That
includes duplicate JSON member names, lone surrogates, integers outside the I-JSON range of plus or minus
(2^53 - 1), a byte order mark, non-canonical
base64, any non-DER encoding in a token, a `GeneralizedTime` outside RFC 3161 2.4.2, and, under `--ed25519 strict`,
a signature whose R is not canonical or is of small order. An Ed25519 public key in the key file that is not
canonical or not of prime order is not refused: as the signer's key it is `KEY_REJECTED` (profile 1.3 step 2), as
any other entry it is the local block `X_UNUSED_KEY_REJECTED`. Under `--profile 1.2.1` the input is refused, as in
version 0.1.0.

Where a standard says what to do with an unknown element, that rule is followed and listed in `notes`: a
non-critical TSTInfo extension is ignored (RFC 5280 4.2), a critical one is refused, and an unknown PKIStatus is an
error (RFC 3161 2.4.2).

The profile does not define the envelope, key-file or criteria-document formats. The member sets accepted for
them are those found in the published inputs (the 26 documents of the 1.2.1 round and the 27 vectors of 1.3). For the criteria document, only `criteria[].id`, `required` and
`title` are interpreted, and the other members are listed in `notes`. `--unknown-fields report` turns refusals
for unknown members into notes.

## Usage

```
python3 war_verify.py RECORD_OR_VECTOR.json             # exit 0 only with every guard below, 1 otherwise, 2 refused
python3 war_verify.py --vector VECTOR.json              # compare with "expected": exit 0 agree, 3 disagree
python3 war_verify.py --keys fonti/issuer_274159c/checker-keys-live.json --tokens pkix \
        --tsa-roots roots/freetsa_cacert.pem fonti/issuer_274159c/selftest-pass.json      # exit 0 (measured)
```

Exit 0 is stricter than "accepted as stated". It requires all of the following:
- `accepted_as_stated` is true (signature valid, no problem code, commitment order decided);
- the key file came from `--keys`, not from the record's own `inputs.keys`;
- the signing key is not a `status: test` key;
- every time-stamp token whose genTime was used was authenticated with `--tokens pkix`;
- supplied files match the record;
- no key in the key file is rejected by the key rule (`X_UNUSED_KEY_REJECTED`: a bad entry that signs nothing);
- `receipt.key_id` equals `signature.key_id` (under 1.3 a difference is already `SIGNATURE_INVALID`; under
  `--key-id-agreement require`, the 1.2.1 reading, it is only this local block; `--key-id-agreement ignore` drops
  this condition).

Each condition that is not met is listed in `local_blocks` and gives exit 1. The profile fields are unchanged by
these guards, so `--vector` scoring is the profile's. Measured on 2026-10-18 (42b4ed0): vector 01 gives exit 1 with
`local_blocks` `X_KEY_FROM_INPUT`, `X_TEST_KEY` and `X_TSA_NOT_VERIFIED`. The live record gives exit 0 only with
the live key file and `--tokens pkix`.

The report also says where the key came from (`details.key_source`), the signer key's status
(`details.signer_key_status`), and whether each token was authenticated (`details.token_authentication`).
`--keys ""`, repeated options, and `--tsa-roots` without `--tokens pkix` are usage errors (exit 64).

Exit 64 is a usage error. Exit 74 means a check could not run, for example `cryptography` is not importable or
`--tsa-roots` holds no certificate. Every check that can run still runs. The report lists the others in
`cannot_run`, sets `signature_valid` to `null` when the signature could not be checked, and never sets
`accepted_as_stated` to true. Measured with `cryptography` made unimportable (`tests/test_cli.py`): vector 02 gives
exit 74, `signature_valid` `null`, `accepted_as_stated` false. Dependencies: Python 3.9 or newer and
`cryptography`. The `cryptography` package is the Ed25519 arithmetic engine and the X.509 parser for `--tokens pkix`.
Canonicalisation and the DER, CMS and TSTInfo parsers are written here.

## Switches: profile 1.3 by default, the 1.2.1 readings kept

Defaults follow profile 1.3. `--profile 1.2.1` selects every reading this verifier gave to 1.2.1 (the rows marked
"1.2.1"); a switch given explicitly overrides it.

| switch | default | alternative | sentence |
|---|---|---|---|
| `--key-id-source` | `receipt`: the signed `receipt.key_id` names the key | `envelope` (1.2.1) | 1.3 step 2 "verify the Ed25519 signature with the key named by the signed `receipt.key_id`" |
| `--key-id-agreement` | `signature-invalid` | `require` (1.2.1: profile fields unchanged, a local block), `ignore` | 1.3 step 2 "The envelope's `signature.key_id` must equal it, else `SIGNATURE_INVALID`" |
| `--key-rule` | `signer`: the key named by `receipt.key_id`; another bad entry is the local block `X_UNUSED_KEY_REJECTED` | `all-keys`: any bad entry is `KEY_REJECTED`; `refuse` (1.2.1: the input is refused) | 1.3 step 2 "the public key must be a canonical encoding (y < p) of a point of prime order; any other key ... is `KEY_REJECTED` and no signature check is run" |
| `--reference-time` | `earlier` | `covering-token` (1.2.1) | 1.3 step 5 "the **earlier** of `issued_utc` and the genTime of the record's own token when a token covering the record is supplied, else `issued_utc`" |
| `--accuracy` | `widen` | `ignore` (1.2.1), `interval` (RFC 3161 2.4.2 ordering rule, `undetermined` when not provable) | 1.3 step 5 "A token's stated `accuracy` widens its time against \"committed before\"; a token stating none is taken at its genTime; `ordering` is ignored" |
| `--independence-rule` | `derived` | `stated-independent` (1.2.1: only a stated `independent` with the same party) | 1.3 step 8 "a stated `independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`" |
| `--time-agreement` | `truncate`: `committed_at` agrees if it equals genTime cut to its own precision | `exact` | step 5 "a `criteria.committed_at` that disagrees is `CRITERIA_TIME_MISMATCH`" (unchanged in 1.3) |
| `--tokens` | `structural` (imprint and genTime) | `pkix` (RFC 3161/5652/5280 validation) | 1.3 step 9 "The outcome fields cover imprint and time only" |
| `--name-compare` | `exact` | `normalized` (NFKC, casefold, collapsed spaces) | property 3 names parties; no equality rule |
| `--unknown-fields` | `refuse` | `report` | profile silent |
| `--ed25519` | `strict` (canonical R, R not of small order, S < L) | `rfc8032` (RFC 8032 5.1.7 only) | the key itself is governed by `--key-rule` |
| `--correspondence` | `ids-required` (same ids, same `required`) | `strict` (titles too) | step 4 "check the results correspond to the criteria" |

Other decisions taken from the text:

- A criteria token whose imprint does not match gives `CRITERIA_TIMESTAMP_MISMATCH` and the fallback
  (`CRITERIA_COMMITMENT_UNVERIFIED`, `committed_at` used): 1.3 step 5 "Without a usable token (none, or one over
  other bytes), fall back to `committed_at`".
- An imprint matches only if `hashAlgorithm` is SHA-256 (OID 2.16.840.1.101.3.4.2.1) with absent or NULL parameters
  and the 32 bytes are equal (1.3 step 5 "a same-length imprint under another algorithm is not a match"; the
  parameters rule is RFC 5754 2).
- A supplied record token is always checked and, when it covers the record, enters the reference time, whatever the
  unsigned `envelope.timestamp` says (step 6: the unsigned `timestamp.digest_sha256` "never decides the outcome").
  The envelope metadata is only compared (`X_TIMESTAMP_METADATA_DISAGREES`, `X_TOKEN_SUPPLIED_RECORD_DECLARES_NONE`).
  Under 1.3 the unsigned `signature.key_id` no longer selects the key: it can only make the record
  `SIGNATURE_INVALID`. `signature.alg` must be `Ed25519`.
- Derived independence: `undeclared` when the producer has neither a non-blank name nor a key id; otherwise
  `self-checked` when the producer and checker names are equal or their keys collide; otherwise `independent`.
  `INDEPENDENCE_INCONSISTENT` is raised when the stated value differs (this includes a stated `self-checked` with
  distinct parties, and vector 20: stated `independent`, no producer). `SELF_CHECKED` follows the label.
- `CHECKER_NOT_SIGNER` is raised when `parties.checker.key_id` is null, unknown, or resolves to another public key
  than the one `receipt.key_id` names. A rejected key still counts as that key, so vectors 26 and 27 (checker =
  rejected signer key) give `KEY_REJECTED` alone. `KEY_COLLISION` compares public keys, not identifiers, and treats
  keys that differ only by a small-order component as equal.
- `PRODUCER_UNDECLARED` is raised when the producer has neither a non-blank name nor a key id ("follows the parties
  block (no producer named), whatever the record states").
- A result outside the vocabulary gives `RESULT_VOCABULARY`. In the verdict it counts as "not pass": required, and
  no required `fail`, gives `incomplete`.
- No problem code exists for a delivered file whose hash differs (step 3). This verifier reports `files` and
  `X_REMEDIATED_FILE_HASH_MISMATCH` and leaves the profile fields unchanged.
- With no required criterion, property 4 gives `pass` (vacuous). `X_NO_REQUIRED_CRITERION` is raised.
- Leap seconds (`:60`) are refused in both time grammars.

Readings of 1.3 that no published vector pins (each has its own vector in `vectors/` or a test):
- the key rule applies to the key named by `receipt.key_id`; a bad entry that signs nothing does not change the
  profile fields (`--key-rule all-keys` reads "any other key" as the whole key list): omega-28, omega-29;
- a `receipt.key_id` absent from the key file stays `SIGNATURE_INVALID` (the 1.3 text names no other code);
- a rejected key together with a differing envelope `signature.key_id` gives both `KEY_REJECTED` and
  `SIGNATURE_INVALID`;
- widening with the earlier-of rule: the commitment is taken at genTime + accuracy and the reference at
  min(`issued_utc`, covering genTime - accuracy), so "yes" needs the first strictly earlier than the second.
  With no stated accuracy this is exactly the earlier-of rule. A literal reading that first compares the covering
  genTime with `issued_utc` and then widens only a token that won gives a different answer on omega-50;
- `committed_at` (the fallback) and `issued_utc` carry no accuracy.

## What was read

Only these files; their URLs and SHA-256 values are in `SOURCES.json`. The 1.2.1 sources were first fetched on
2026-10-18T06:14:50Z, the 1.3 sources at 2026-10-18T15:31Z:

- `fonti/upstream_42b4ed0/`: profile 1.3 README and vectors 01-27 (maximusrufus/work-acceptance-record@42b4ed0,
  committed 2026-10-18T14:43:42Z). Vectors 01-11 are byte-identical to f7d8984. Vectors 12-23 have the same
  `inputs` as the copies listed below (12 is 12b); only metadata changed, and vector 20's `expected` (now with
  `INDEPENDENCE_INCONSISTENT`, the contributor's expectation stated in a `difference` member);
- the rulings comment of the profile author on x402-foundation/tsc#4 (issuecomment-6251239282, 14:44:09Z), read
  with `gh api`; the README text was checked for each ruling. A later comment of the same author
  (issuecomment-6251573298, posted 15:17:28Z, edited 15:44:33Z) is about their implementations and states no ruling;
- `fonti/upstream_f7d8984/`: profile 1.2.1 README and vectors 01-11 (maximusrufus/work-acceptance-record@f7d8984);
- `fonti/tetsurohhori_4f6cf49/`: proposed vectors 12-21 and `TEST_KEY.json`;
- `fonti/babyblueviper1_431525f/`: proposed vectors 22-23;
- `fonti/tetsurohhori_8ff69f4/`: proposed vectors `12b-signer-is-not-the-checker` and `22-criteria-token-sha1-imprint`,
  posted on 2026-10-18 at about 07:10Z;
- `fonti/issuer_274159c/`: the issuer's `selftest-pass.json`, its README and `checker-keys-live.json` (the live key file).
  Its `keys` equal the `keys` embedded in `selftest-pass.json`.

The following standards were fetched from rfc-editor.org on 2026-10-18 (the first 16 hex digits of each SHA-256 are
given): RFC 8785 (63d52294eb0e3f00), RFC 8032 (ed63657ff3893012), RFC 3161 (39fd17644ff2d654), RFC 5652
(dbd209ae7844031f), RFC 5280 (a2f2628c0a83b873), RFC 5816 (9a3eba6ecf14afc7), RFC 7493 (a44ccf1451a7bf4f),
RFC 3339 (9ab2b8864a85dca7) and RFC 5754 (13d095299ffec21b). X.690 (DER) and the ESS attribute definitions
(RFC 2634, RFC 5035) were applied from their known rules and not re-read.

TSA certificates (in `roots/`, fetched from freetsa.org/files on 2026-10-18T06:16Z): `freetsa_cacert.pem`
(SHA-256 of the file 2151b611…, certificate fingerprint A6:37:9E:7C…) and `freetsa_tsa.crt`. No DigiCert root
was fetched: the record contains no DigiCert token.

The issuer README points to its own verifier (`war_check.py`). It was not opened, and no other verifier, builder or
runner for this profile was opened. For the composition section only, this project's own x402 acceptance-record
checker was read and run. The vectors' own descriptions state their contributors' readings. On the points those
descriptions decide, this verifier is not independent of them. The reading of each point is in "Switches" and in
the `reading` field of the new vectors. Vectors 24 and 25 of 1.3 are listed in the profile README as "case from
robertolocatelli81-dev", and the rulings comment says they "cover @robertolocatelli81-dev's omega-15 and omega-16",
two vectors of this project: agreement on 24 and 25 is not independent evidence.

## Results (measured 2026-10-18; numbers per the commit that adds this README)

Defaults (profile 1.3): the 27 vectors of 42b4ed0 and the live record, compared field by field, with code lists
compared as sets (`tools/score.py`, `results/score_default.txt`):

| document | fields | outcome |
|---|---|---|
| 01-20, 22-27 | 9/9 each | agree |
| 21-unknown-schema | 2/2 (`refused`, `reason`) | agree |
| selftest-pass (live record) | 9/9 | agree |

Total: 28/28 documents, 245/245 fields.

Vector 20, both readings reported. The file's `expected` (profile author) has `INDEPENDENCE_INCONSISTENT` and the
`PRODUCER_UNDECLARED` warning; this verifier agrees. Its `difference` member states the contributor's expectation,
"problem_codes [] (warning only)"; against it this verifier disagrees on `problem_codes` (ours
`INDEPENDENCE_INCONSISTENT`). The sentence that decides it is 1.3 step 8: "a stated `independence` that differs from
the derived one is also `INDEPENDENCE_INCONSISTENT`" (stated `independent`, derived `undeclared`). With
`--independence-rule stated-independent` the two results swap: the contributor's expectation agrees, the file's
does not.

Each other value of each switch, on the same 28 documents (`results/score_*.txt`):

| switch | documents agreeing | what changes |
|---|---|---|
| `--reference-time covering-token` | 27/28 | 22: `yes` and no problem, expected `no` and `CRITERIA_COMMITTED_AFTER_CHECK` |
| `--key-rule refuse` | 26/28 | 26 and 27 refused, expected `KEY_REJECTED` |
| `--independence-rule stated-independent` | 27/28 | 20, as above |
| `--accuracy interval` | 12/28 | 16 "yes" become `undetermined`: no vector token states an `accuracy` |
| `--profile 1.2.1` (all six 1.2.1 readings) | 24/28 | 20, 22, 26, 27 |
| `--key-id-source envelope`, `--key-id-agreement require`, `--key-id-agreement ignore`, `--key-rule all-keys`, `--accuracy ignore`, `--time-agreement exact`, `--name-compare normalized`, `--correspondence strict`, `--ed25519 rfc8032`, `--unknown-fields report` | 28/28 each | none: no 1.3 vector separates them (own vectors and tests do) |

Version 0.1.0 of this verifier (the previous commit), run unchanged on the same 28 documents with vector 20's
`difference` member removed (0.1.0 refuses unknown vector members), also gives 24/28 with the same four
disagreements; `--profile 1.2.1` reproduces it.

The 1.2.1 round (23 vectors, 12b, 22-sha1 and the live record, `--set 1.2.1`): with `--profile 1.2.1`, 25/26
documents and 225/227 fields, as measured for 0.1.0 (only 22 disagrees). With the 1.3 defaults, 24/26 and 224/227:
22 now agrees; the old 12 (`signature.key_id` hori-cold-test-2, signed `receipt.key_id` hori-cold-test-1) gives
`SIGNATURE_INVALID` (1.3: "12b replaces 12"); the old 20 gives `INDEPENDENCE_INCONSISTENT` (1.3 amended 20).

Positive controls of the scoring bench: a verifier that always answers "valid, pass, no codes" agrees with 0/28
documents. Corrupting one expected field in every vector is detected 28/28 (`tests/test_vectors.py`).

## Beyond the profile

### RFC 3161 validation of the live record (`--tokens pkix`)

Both tokens of `selftest-pass.json` (criteria token, genTime 2026-10-18T00:52:03Z, and record token,
00:52:09Z) are checked as follows:

- one SignerInfo;
- the content-type and message-digest attributes;
- the ESS signing-certificate attribute binding the signer certificate (the live tokens use ESSCertID v1, SHA-1);
- the signature over the DER signed attributes;
- the EKU, exactly id-kp-timeStamping and critical;
- `TSTInfo.tsa` names the signer;
- every certificate valid at genTime;
- a path to the root fetched from freetsa.org (the root embedded in the token is not trusted).

Result: `valid` for both, and `openssl ts -verify` agrees. Both tokens carry `ordering` TRUE and the same TSA name,
so under RFC 3161 2.4.2 their order is provable even though neither has an `accuracy` field.

Fifteen cases from a throw-away test TSA give the positive controls, and each is compared with
`openssl ts -verify` (OpenSSL 3.0.22). Twelve cases agree with OpenSSL: the two valid tokens (ESS v1 and v2), and
ten invalid ones (signature flipped, message-digest wrong, no ESS attribute, ESS hash of another certificate, two
SignerInfos, EKU not critical, EKU serverAuth, EKU timeStamping plus codeSigning, no EKU, signed by another key).
Three cases differ:
- a token whose TSA certificate had expired at genTime, and one whose TSA certificate was not yet valid at genTime.
  `openssl ts -verify` checks certificates at the current time unless `-attime` is given (its documented default);
  with `-attime` set to genTime it rejects both (measured). This verifier checks every certificate at genTime. That
  is a choice of validation time (RFC 5280 6.1.1), not a sentence of RFC 3161 about the TSA certificate.
- a token whose content-type attribute is id-data while `eContentType` is id-ct-TSTInfo. RFC 5652 11.1 says the two
  MUST match. OpenSSL 3.0.22 accepts it; the missing check is a known open OpenSSL issue (openssl/openssl#9009,
  2019). This verifier rejects it.

OpenSSL 3.0.22 refuses to parse all 31 token occurrences (11 distinct tokens) in the 25 vectors of the 1.2.1 round
(`Field=signer_info ... field missing`; not re-run on the 1.3 vectors 24-27, whose README now calls the vector tokens
"imprint-and-time fixtures, not valid RFC 3161 tokens"). They omit
`signerInfos`, which RFC 5652 5.1 does not make optional. In `--tokens structural` mode they are accepted and
flagged `X_TOKEN_NOT_CMS_CONFORMANT`. In `--tokens pkix` mode they are refused.

### Ed25519 edge cases (`tools/ed25519_edges.py`, `results/ed25519_edges.txt`)

| case | `cryptography` engine alone | RFC 8032 pure | this verifier, strict |
|---|---|---|---|
| identity public key, R = identity, S = 0, any message | accepts | accepts | rejects; as the signer's key, `KEY_REJECTED` with no signature check (vector 26) |
| non-canonical public key (y = 1 + p), same signature | accepts | rejects | rejects; `KEY_REJECTED` (vector 27) |
| S + L | rejects | rejects | rejects |
| public key of order 2, R = identity, S = 0 | 29 of 64 messages | 29 of 64 | 0 |
| key A + T8, signed by A's scalar with k hashed over A + T8 | 35 of 256 messages (this seed; about 1 in 8 expected) | 35 of 256 | 0 |
| same, grinding the nonce for one chosen message | succeeds at try 2 here; about 8 tries expected | | |

The first two rows are known behaviour: an identity public key with R = identity and S = 0 verifies under RFC 8032
itself, and OpenSSL and pyca/cryptography accept a non-canonical public-key encoding (the classes of
ed25519-speccheck cases 0 and 11, published in 2020). They were measured again on 2026-10-18 with
`cryptography` 50.0.1 and 50.0.2 and with the `openssl` 3.0.22 command line. The last two rows show one private scalar producing signatures under two public keys with different
bytes. A `KEY_COLLISION` test that compares key bytes or key ids misses this; a party can also present two unrelated
keys, which no key comparison can detect. This verifier rejects keys that are not canonical or not of prime order
(`KEY_REJECTED`, profile 1.3; refused under `--profile 1.2.1`) and compares keys modulo the small-order subgroup.
The "strict" column is the signature primitive (`ed25519_verify`); the key rule runs before it, and
`tests/test_profile13.py` checks that no signature check runs for a rejected key (8 key encodings).

### Generative attack (`tools/fuzz.py`, `results/fuzz.txt`)

597 generated cases in 10 families, each with an expectation written from the text (profile 1.3; at 1.3 five
expectations and one case's `issued_utc` changed and one case was added, each with the sentence in `tools/fuzz.py`). This verifier meets all 597. The
deliberately lax verifier `tools/lax_verify.py` is the positive control: it fails 560, and wrongly reports 416 as
accepted as stated.

| family | cases | lax verifier fails |
|---|---|---|
| unknown member at every object level | 21 | 21 |
| duplicate member at every object level | 21 | 21 |
| wrong type at every leaf | 418 | 412 |
| lone surrogate in every receipt string | 40 | 39 |
| numbers (1e21, 5e-324, 1.0, 2^53+1, -1, 1E2, -0, 0) | 24 | 18 |
| DER / TSTInfo (lengths, trailing bytes, all same-length hash OID swaps, params, nonce/extension smuggling, GeneralizedTime grammar, ordering FALSE, status) | 41 | 36 |
| Ed25519 | 5 | 3 |
| key_id confusion across envelope, receipt and parties | 7 | 4 |
| time ties and grammar | 10 | 5 |
| criteria file bytes (BOM, CRLF, NFC/NFD, trailing newline) | 10 | 1 |

### Composition with a counterparty acceptance (`tools/compose.py`, `results/compose.txt`)

`~/progetti/x402-acceptance-check-omega/acceptance_check.py` (commit 075ae1b) was run unchanged, on its own
grammar:

- a work-acceptance `receipt` passed as `accepted_record` is refused (input_error: 17 unknown members). Its
  `accepted_record` is a flat object of strings.
- a string projection (`issuer`, `issuer_kid`, `terms_sha256` = `criteria.sha256`, `outcome_sha256` =
  `files.remediated.sha256`, `outcome_at`, `record_id` = `war-sha256:` + SHA-256 of the canonical receipt) is
  `verified`.
- `outcome_at` must have exactly three fractional digits; `issued_utc` copied as is (seconds) is refused.
- the same acceptance stays `verified` when the relying party holds a different work-acceptance record. It also
  stays `verified` when the accepted record's recomputed verdict is `fail`. Only the glue check in `compose.py`
  catches these: `record_id` must equal the SHA-256 of the canonical receipt of the record held (the first case),
  and the relying party must read that record's recomputed verdict (the second case: the record verifies and is
  bound, and its verdict is `fail`).
- an acceptance signed with the checker's own key gives `acceptance_signer_is_issuer`, so the two parties stay
  separate.

Missing for an unchanged composition: a member carrying the work-acceptance digest as a checked binding, not as a
free-form `record_id`; one time format; and a rule saying that the relying party verifies the referenced record.

## Tests

```
python3 tools/fetch_sources.py                   # third-party inputs, pinned by SHA-256 (needs network once)
python3 -B -m unittest discover -s tests          # 76 tests
sh tools/run_results.sh                           # regenerates results/ (scores, fuzz, Ed25519, live record, composition)
```

Measured on 2026-10-18: 76/76 pass on Python 3.9.25 and 3.13.15 with `cryptography` 50.0.2, and on 3.11.2 with
`cryptography` 50.0.1. Every test file has its positive control:
- the scoring bench fails an accept-always verifier (0/28);
- each 1.3 rule in `tests/test_profile13.py` has a control case (its 1.2.1 reading, another switch value or an
  input on the other side of the rule), and each of the 14 own vectors with an `expected_1_2_1` disagrees under
  the other reading;
- the JCS table fails a naive `repr` (10/24 rows wrong);
- each Ed25519 vector fails with one flipped byte;
- every TSA case is compared with `openssl ts -verify`;
- the generative attack catches the lax verifier in every family.

`tests/nemesis_r1_check.py` and `tests/_nemesis_forge.py` come from the first independent review of this verifier,
and `tests/test_nemesis_r2.py` (7 tests) from the second; each of its tests kills a mutant that survived the battery
below (unimplemented TSA signature algorithm, certificate validity bounds, TSTInfo.tsa name, empty signerInfos,
ordering tie, producer key in the key file, y = p).
They are kept unchanged except the subprocess flags (`-I` replaced by `-B` with `PYTHONPATH` removed, because `-I`
hides a user-site `cryptography`), and are run by `tests/test_nemesis_wrapper.py`. The round-1 checks were written
for 1.2.1: the wrapper runs them with the 1.2.1 readings as defaults (all pass) and with the 1.3 defaults, where
exactly six fail, each for a 1.3 sentence: old vector 12 (12b replaces it), old vector 20 (amended), M41 (the
unsigned `signature.key_id` no longer names the signer), M59, M60 and F11 (a bad key is `KEY_REJECTED`, not refused
or accepted with a note).

## Mutation battery (`tools/mutate.py`, `tools/mutation_report.py`, `results/mutation*.json`)

### Spot-check of the profile 1.3 changes (`results/mutation13.json`)

The same operators, restricted with `--only` to the sites on lines changed for 1.3 (`check_keyfile` and `verify`;
the CLI excluded): 72 mutants. Suites: the 27 vectors of 1.3, the live record, the 52 own vectors,
`tests/test_profile13.py`, `tests/test_local_blocks.py`, and the alternative readings (`OPTION_SETS` in
`tools/mutate.py`) on the 23 vectors of the 1.2.1 round, the live record and the 52 own vectors. First pass:
67 killed, 5 survivors. One (the tie between `issued_utc` and a covering token, which changes only the label of the
reference) is killed by the unit-test suite; for the other four, three assertions were added to
`tests/test_profile13.py` (the `rejected_keys` detail, the exact 1.2.1 refusal reason for a 31-byte key, a weak key
under `--profile 1.2.1 --ed25519 rfc8032`), and all four are killed. Result: 72/72 killed.

### Full battery (version 0.1.0; not re-run for 0.2.0)

Mutation operators, applied to `war_verify.py` 0.1.0 (SHA-256 560a6200…cb65, the file before the second review
changed one comment and the module docstring) at each site:
- every comparison flipped;
- every `and`/`or` swapped;
- every `not` removed;
- every `raise` and every `.add(...)` statement removed;
- every `if` test forced to False.

The module-level `__main__` guard is excluded. This gives 1073 mutants. Each runs in its own process, writes its
own result file, and has a timeout. A mutant is killed when any compared outcome differs from the original's.

| suites so far | surviving mutants |
|---|---|
| the 23 vectors | 736 |
| + the 43 new vectors | 597 |
| + the generative attack (596 cases) | 555 |
| + unit tests, the alternative readings on all vectors, the review's checks | 359 |
| + `tests/test_local_blocks.py` | 324 |

Of the kills, 23 are by exception and 1 by timeout.

42 of the 43 vectors of 0.1.0 each kill at least one mutant that passes all 23 published vectors; that mutant is a lax
verifier that the vector catches while this verifier agrees. The vector-to-mutant map is in `results/mutation.json`.
omega-08 kills none.

What the 324 survivors are:
- `verify_tsa` (44): pkix checks without a negative case;
- `main` (44): the CLI, tested only through subprocesses;
- `verify` (26): mostly extension-code bookkeeping;
- DER and JSON guards (`_der_tlv` 21, `parse_token` 19, `parse_tstinfo` 16, ...): mostly guards whose removal
  lets a later check refuse the same input with another reason.

They are not proven equivalent. In `_jcs_number`, a boundary test added afterwards (0.5, 1e20) kills 2 of the 11
survivors. From reading the code, the other 9 look unreachable from the parser, but that is not proven.

## New vectors (`vectors/`, CC0)

52 vectors. They are signed with the `omega-test-1` and `omega-test-2` TEST keys, whose private seeds are
published in every vector (never trust them), and are built by `tools/make_vectors.py`. Each `expected` object was
written from the text; the sentence used is in the vector's `reading` field. `expected_extensions` lists this
verifier's own `X_` codes and is not part of the profile. Where this verifier's 1.2.1 reading gives other profile
fields, they are in `expected_1_2_1`.

At 1.3, the `inputs` of omega-01 to omega-43 are unchanged (rebuilt byte for byte). Seven expectations changed, each
with the 1.3 sentence in `reading`:
- omega-11 (signed `receipt.key_id` names the other key): `SIGNATURE_INVALID` and `CHECKER_NOT_SIGNER` (step 2);
- omega-21, omega-24, omega-25 (`issued_utc` 12:00:00, not later than the commitment, is earlier than the covering
  token): `no` and `CRITERIA_COMMITTED_AFTER_CHECK` (step 5, earlier-of);
- omega-27 (identity key signs): `KEY_REJECTED`, `signature_valid` false;
- omega-28, omega-29 (a bad key that signs nothing): the profile fields of a valid record and the local block
  `X_UNUSED_KEY_REJECTED` (previously refused).

Nine vectors were added for the 1.3 rulings: omega-44 (envelope `key_id` differs), omega-45 (signer key of mixed
order), omega-46 to omega-49 (accuracy widening, no accuracy, `ordering` ignored, with `issued_utc` later than the
tokens), omega-50 (widening against `issued_utc`, a reading no published vector pins), omega-51 and omega-52 (stated
`self-checked` against a derived `independent` or `undeclared`).

This verifier agrees with 52/52 under the defaults, and with 52/52 under `--profile 1.2.1` against
`expected_1_2_1` (or `expected` where the readings agree). The lax verifier is wrong on 41/52.
