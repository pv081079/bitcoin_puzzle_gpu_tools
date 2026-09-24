# bitcoin-puzzle-gpu-tools

Two validated, GPU-accelerated (CUDA) tools that generate random
candidate private keys via two different historical Bitcoin key
derivation schemes, and check a specific derivation index against a
target `hash160`:

- **`mnemonic_search.cu`** — random BIP39 mnemonics (12 or 24 words) → BIP32 HD derivation
- **`armory_search.cu`** — random 32-byte seeds → Armory's pre-BIP32 sequential derivation scheme

Both share the same secp256k1 engine (Jacobian coordinates + a
secp256k1-specific fast field reduction + block-level Montgomery
batch modular inversion), and the same masking step described below.

## ⚠️ Read this before running

**`mnemonic_search`** searches a space of **~2^128** (12 words) or
**~2^256** (24 words) possible mnemonics. **`armory_search`** searches
a space of **~2^256** possible 32-byte seeds. For comparison, a 2^70
brute-force search — already considered computationally infeasible by
the Bitcoin puzzle-solving community (projected at hundreds of years
with all current combined hardware) — is smaller than either space by
many orders of magnitude.

**No realistic amount of GPU time will find a specific target this
way.** Both tools exist as validated technical exercises — correctly
implemented, GPU-accelerated cryptographic pipelines — not as viable
key-recovery strategies. Every primitive was independently checked
against official test vectors, and the Armory implementation was
additionally cross-validated against the real output of the
[`vuke`](https://github.com/oritwoen/vuke) research tool. See
`validation/`.

## What each tool does

### `mnemonic_search.cu`

Per GPU thread, per attempt:
1. Generate random entropy (128 or 256 bits)
2. Compute the BIP39 checksum and build a valid mnemonic sentence
   (12 or 24 words from the standard English wordlist)
3. Derive the BIP39 seed via `PBKDF2-HMAC-SHA512` (2048 iterations)
4. Derive the BIP32 master key (`HMAC-SHA512("Bitcoin seed", seed)`)
5. Derive `m/0/<puzzle_index>` via standard non-hardened BIP32 child
   derivation
6. Apply the mask (see *About the mask*), `hash160` the result,
   compare against the target

### `armory_search.cu`

Per GPU thread, per attempt:
1. Generate 32 random bytes, treated as a candidate seed
2. `root = SHA256(seed)`
3. `chaincode = HMAC-SHA256(key=SHA256(SHA256(root)), msg="Derive Chaincode from Root Key")`
4. Walk `puzzle_index` **sequential** steps from `root` (Armory has no
   random-access indexing like BIP32 — reaching child `N` requires
   computing children `1..N-1` first):
   - `pubkey = current_priv · G` (uncompressed, 65-byte serialization)
   - `A = SHA256(SHA256(pubkey)) XOR chaincode`
   - `current_priv = (current_priv × A) mod N` — **multiplication**,
     not addition (this is the key structural difference from BIP32,
     which replaced Armory's multiplicative step with an additive one
     specifically for simpler implementation — see BIP-32's changelog)
5. Apply the mask, `hash160` the result, compare against the target

Because step 4 is sequential, `armory_search`'s per-attempt cost grows
roughly linearly with `puzzle_index` (each step needs its own point
multiplication), unlike `mnemonic_search`'s roughly constant 3
point-multiplication cost per attempt.

## About the mask

`P[n] = 2^(n-1) | (K mod 2^(n-1))` reflects a specific, publicly
documented pattern used by the "Bitcoin puzzle" transaction series:
private keys constrained to fall within `[2^(n-1), 2^n)` for a chosen
`n`. Both tools were originally built to test whether Electrum 1.x,
BIP32/BIP39, or Armory-style deterministic wallets could plausibly
explain those specific keys, validating candidate seeds against the
already-solved puzzles in that series. Strip the mask out (use the raw
derived key directly) to search for an arbitrary target instead.

## Build

Requires the CUDA toolkit (`nvcc`) and an NVIDIA GPU.

```bash
nvcc -O3 -arch=sm_75 mnemonic_search.cu -o mnemonic_search
nvcc -O3 -arch=sm_75 armory_search.cu -o armory_search
```

Adjust `-arch=sm_75` to match your GPU's compute capability
(`sm_75` = Turing, e.g. Tesla T4/RTX 20-series; `sm_86` for Ampere/RTX
30-series; `sm_89` for Ada/RTX 40-series; etc).

## Usage

```bash
./mnemonic_search <target_hash160_hex_40chars> <puzzle_index> <12|24> [total_threads_per_batch]
./armory_search    <target_hash160_hex_40chars> <puzzle_index> [total_threads_per_batch]
```

- `target_hash160_hex`: 40 hex characters (20 bytes)
- `puzzle_index`: the mask parameter `n` — also, for `armory_search`,
  the number of sequential derivation steps to walk
- `12`/`24` (mnemonic_search only): word count
- `total_threads_per_batch` (optional, default `1000000` /
  `128000` respectively): GPU threads launched per batch

Both run **indefinitely**, launching batches with a new random seed
each time, reporting progress every 5 seconds, until a match is found
or interrupted (`Ctrl+C`).

### Example

```bash
./mnemonic_search b907c3a2a3b27789dfb509b730dd47703c272868 20 12
./armory_search    b907c3a2a3b27789dfb509b730dd47703c272868 20
```

(Puzzle #20's real, already-solved `hash160` — useful to confirm both
pipelines run correctly. **Caution**: low `puzzle_index` values like
`20` have a tiny effective output space after masking (`2^19`
possibilities), so random matches occur by pure chance at this scale
and are **not** evidence of anything — see *A statistical trap* below.)

### A statistical trap worth knowing about

The mask limits the *output* to `2^(n-1)` possible values for puzzle
index `n`. For low `n` (e.g. `20`), that's only `524,288` possible
outcomes — small enough that testing hundreds of thousands of random
candidates will produce an apparent "match" by pure chance,
**independent of whether the underlying hypothesis has any merit**.
For `n=20` specifically, the expected number of chance matches after
`N` attempts is `N / 2^19`; with `128,000` attempts that's `~0.24` —
so seeing one hit is unremarkable. Only treat a match as meaningful
evidence for `n` large enough that `2^(n-1)` comfortably exceeds your
total attempt count (e.g. `n ≥ 37` for search volumes up to
low billions).

## Performance

Both use block-level Montgomery batch modular inversion (one shared
inversion per block of threads per elliptic-curve point needed,
instead of one inversion per thread) — the same technique used by
this project's separate `amalia_hier_leaf` hierarchical-lookup tool,
adapted here to a per-attempt random-search kernel. Actual throughput
depends on your GPU; `armory_search`'s cost scales with
`puzzle_index` due to its sequential derivation structure.

## Validation

Every primitive was checked against official test vectors in plain
C/C++ **before** being ported to CUDA device code, and each full
pipeline was then re-validated on actual GPU hardware — including the
new block-level batch-inversion kernel structure specifically (128
threads, identical fixed input, checked that all 128 independently
converge to the same, correct answer).

| Component | Test vector | Source |
|---|---|---|
| SHA-512 | `SHA512("abc")`, `SHA512("")` | NIST |
| HMAC-SHA512 | RFC 4231 Test Case 1 | IETF |
| HMAC-SHA256 | RFC 4231 Test Case 1 | IETF |
| PBKDF2-HMAC-SHA512 | BIP39 seed for the "zoo...vote" mnemonic | BIP-0039 |
| entropy → mnemonic | all-1-bits entropy → "zoo"×23 + "vote" | BIP-0039 |
| secp256k1 field/point ops | `K·G` for known puzzle #64 private key; `2^k·G`; Fermat's little theorem | this project |
| Montgomery batch inversion | 16-value batch vs. 16 individual inversions | this project |
| Full BIP32 derivation | `m/0/1` from the "zoo...vote" mnemonic | cross-checked independently in Python |
| **Armory chaincode + sequential derivation** | **4-step-advance output for seed `"teste_armory"`, matched byte-for-byte against real [`vuke`](https://github.com/oritwoen/vuke) 0.9.0 CLI output** | **live cross-validation, this project** |
| Batched search kernels (128 threads, shared inversion) | all threads converge to the single-thread reference result | this project |

See `validation/` for the individual C/C++ test programs (compile any
of them with `g++ -O2 -x c++ <file>.c -o test && ./test`).

## License

MIT — see source file headers. No warranty; this is research/
educational code.
