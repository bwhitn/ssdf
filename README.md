# Content Similarity Prototype

This directory contains a standalone prototype for the file-content similarity
value emitted by the Zeek analyzer:

```text
content_sim_alg=mh-buz32-96-192-w12-k24-h18-hh64-b64url
content_sim=<24 colon-separated 3-character base64url tokens>
```

The implementation hashes content bytes only. It does not use file names, MIME
types, sizes, protocol metadata, endpoint metadata, or exact file hashes as
features.

## Algorithm

The streaming hasher:

1. Maintains 32-byte, 96-byte, and 192-byte rolling buzhash windows.
2. Applies a splitmix64-style avalanche to each rolling hash.
3. Selects features through winnowing with a 12-feature minimizer window.
4. Updates an internal 80-row MinHash signature from each selected feature.
5. Emits the first 24 MinHash rows as row-scoped 18-bit tokens.
6. Mixes the algorithm id, row index, and MinHash row value with HighwayHash
   and a fixed public algorithm key.
7. Truncates each row hash to 18 bits and encodes it as 3 unpadded RFC4648
   base64url characters.

Base64url encoding is implemented directly for the fixed 18-bit to 3-character
case.

The output has 24 ordered tokens, uses `:` as the separator, and has a total
string length of 95 characters.

## CLI

Build with:

```bash
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

```bash
build/content-sim FILE
build/content-sim --compare FILE FILE
build/content-sim --minhash18x24 FILE
build/content-sim --minhash18x24-compare FILE FILE
build/content-sim --chunk-test FILE
build/content-sim --benchmark [FILE ...]
```

`content-sim FILE` prints:

```text
mh-buz32-96-192-w12-k24-h18-hh64-b64url <content_sim>
```

`--minhash18x24` and `--minhash18x24-compare` are aliases for the current
default hash and comparison modes. The older `--minhash18x32` aliases are still
accepted for ad-hoc compatibility.

`--compare` hashes two files and reports raw MinHash row agreement across the
internal 80-row signature, row agreement across the emitted 24 rows, emitted
token agreement, and both content similarity strings.

`--chunk-test` hashes the same file with 1-byte, 7-byte, 64-byte, 4096-byte, and
whole-file update calls and exits non-zero if the output differs.

`--benchmark` reports bytes processed, elapsed seconds, MB/s, rolling-window
count, selected-feature count, MinHash update count, and the final
`content_sim`. It always benchmarks generated random and repeated data, and also
benchmarks any file paths passed on the command line.

## Sample PCAP

`samples/near-identical-http-files.pcap` contains two HTTP downloads,
`alpha.bin` and `alpha-near.bin`. The second body is the first body with a small
inserted block in the middle. Regenerate it with:

```bash
python3 samples/make-near-identical-http-pcap.py
```

## Zeek Integration Notes

The `base/files/content-sim` script extends `Files::Info` with
`content_sim_alg` and `content_sim`, and the `Zeek::FileContentSim` analyzer
emits:

```text
content_sim_alg=mh-buz32-96-192-w12-k24-h18-hh64-b64url
content_sim=<24 colon-separated 3-character base64url tokens>
```

For ad-hoc testing across all observed files, load:

```zeek
@load policy/frameworks/files/content-sim-all-files
```

Zeek should only emit `content_sim` after confirming complete file observation.
Do not emit it when `missing_bytes != 0`, `overflow_bytes != 0`, `timedout == T`,
or the hasher returns no value because too few bytes or selected features were
observed.

Use existing file-log fields such as `total_bytes` and `mime_type` for ranking
or filtering candidate comparisons. They should not be input features for this
similarity value.
