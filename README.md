# SSDF Prototype

This directory contains a standalone prototype for the file-content similarity
value emitted by the Zeek analyzer:

```text
content_sim_alg=ssdf-alpha
content_sim=<24 colon-separated 3-character base64url tokens>
```

The implementation hashes content bytes only. It does not use file names, MIME
types, sizes, protocol metadata, endpoint metadata, or exact file hashes as
features.

`ssdf-alpha` is intentionally not a compatibility-stable identifier. The exact
recipe below documents the current alpha behavior; future incompatible alpha
changes may keep this short log value until the first stable `ssdf-v1` recipe is
chosen.

## Algorithm

The streaming hasher:

1. Maintains 64-byte and 192-byte rolling buzhash windows.
2. Uses a row-split MinHash signature: rows 0-11 use 64-byte winnowed
   minimizers and rows 12-23 use sparse content-defined samples from the
   192-byte lane.
3. Selects the winnowed lane with a 12-feature minimizer window. Before a
   64-byte rolling window enters the minimizer queue, it must pass a
   content-defined 1/4 pre-gate. A selected minimizer must also pass a
   content-defined 1/4 post-gate before updating the first 12 MinHash rows.
4. Selects the sparse CDC lane when the raw rolling feature passes a 1/128
   gate, then applies a splitmix64-style avalanche before MinHash.
5. Emits the MinHash rows as row-scoped 18-bit tokens.
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

For speed measurements, use a stripped native Release build so debug metadata
and generic CPU code do not skew the numbers:

```bash
cmake -S . -B build-perf \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
  -DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG -march=native -fomit-frame-pointer" \
  -DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG -march=native -fomit-frame-pointer"
cmake --build build-perf -j$(nproc)
strip build-perf/ssdf build-perf/ssdf-tests
build-perf/ssdf --benchmark [FILE ...]
```

```bash
build/ssdf FILE
build/ssdf --compare FILE FILE
build/ssdf --minhash18x24 FILE
build/ssdf --minhash18x24-compare FILE FILE
build/ssdf --chunk-test FILE
build/ssdf --benchmark [FILE ...]
```

`ssdf FILE` prints:

```text
ssdf-alpha <content_sim>
```

`--minhash18x24` and `--minhash18x24-compare` are aliases for the current
default hash and comparison modes. The older `--minhash18x32` aliases are still
accepted for ad-hoc compatibility.

`--compare` hashes two files and reports raw MinHash row agreement, row
agreement across the emitted 24 rows, emitted token agreement, and both content
similarity strings.

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
content_sim_alg=ssdf-alpha
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
