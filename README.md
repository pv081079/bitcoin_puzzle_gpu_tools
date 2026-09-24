# bitcoin-puzzle-gpu-tools

Three validated, GPU-accelerated (CUDA) tools that generate random
candidate private keys via three different historical Bitcoin key
derivation schemes, and check a specific derivation index against a
target `hash160`:

- **`mnemonic_search.cu`** — random BIP39 mnemonics (12 or 24 words) → BIP32 HD derivation
- **`armory_search.cu`** — random 32-byte seeds → Armory's pre-BIP32 sequential derivation
- **`casascius_search.cu`** — random passphrases → Casascius Bulk Address Utility's key formula

All three share the same secp256k1 engine (Jacobian coordinates + a
secp256k1-specific fast field reduction; `mnemonic_search` and
`armory_search` additionally use block-level Montgomery batch modular
inversion), and the same masking step described below.

## ⚠️ Read this before running

All three tools search spaces of **~2^128** to **~2^256** possible
random inputs. For comparison, a 2^70 brute-force search — already
considered computationally infeasible by the Bitcoin puzzle-solving
community (projected at hundreds of years with all current combined
hardware) — is smaller than any of these spaces by many orders of
magnitude.

**No realistic amount of GPU time will find a specific target this
way.** All three tools exist as validated technical exercises —
correctly implemented, GPU-accelerated cryptographic pipelines — not
as viable key-recovery strategies. Every primitive was independently
checked against official test vectors or the published reference
source, and the Armory implementation was additionally cross-validated
against the real output of the
[`vuke`](https://github.com/oritwoen/vuke) research tool. See
`validation/`.

## What each tool does

### `mnemonic_search.cu` (BIP39/BIP32)

Per GPU thread, per attempt: generate random entropy → build a valid
BIP39 mnemonic (12 or 24 words) → `PBKDF2-HMAC-SHA512` seed (2048
iterations) → BIP32 master key → derive `m/0/<puzzle_index>` →
mask → `hash160` → compare.

### `armory_search.cu`

Per GPU thread, per attempt: 32 random bytes as seed → `root =
SHA256(seed)` → `chaincode = HMAC-SHA256(SHA256(SHA256(root)), "Derive
Chaincode from Root Key")` → walk `puzzle_index` **sequential** steps
(Armory has no random-access indexing — reaching child `N` requires
computing children `1..N-1` first):
```
pubkey = current_priv · G   (uncompressed, 65-byte serialization)
A = SHA256(SHA256(pubkey)) XOR chaincode
current_priv = (current_priv × A) mod N     ← multiplication, not addition
```
then mask → `hash160` → compare. The multiplicative step is the key
structural difference from BIP32, which replaced it with addition
specifically for simpler implementation (see BIP-32's own changelog).
Because derivation is sequential, per-attempt cost grows roughly
linearly with `puzzle_index`.

### `casascius_search.cu`

Per GPU thread, per attempt: random passphrase bytes (hex-encoded) →
build the string `"{n}/{passphrase}/{n}/BITCOIN"` → `SHA256` → mask →
`hash160` → compare. This is the simplest of the three: the formula
comes directly from the *official* Casascius Bitcoin-Address-Utility
source code (`Walletgen.cs`) — `PrivKey = SHA256(n + "/" + passphrase
+ "/" + n + "/BITCOIN")`, `n = "1"` through `"10"` in the original
tool's UI (this implementation accepts any `n`, since the puzzle
context calls for indices beyond that original 1–10 range).

## About the mask

`P[n] = 2^(n-1) | (K mod 2^(n-1))` reflects a specific, publicly
documented pattern used by the "Bitcoin puzzle" transaction series:
private keys constrained to fall within `[2^(n-1), 2^n)` for a chosen
`n`. All three tools were originally built to test whether Electrum
1.x, BIP32/BIP39, Armory, or Casascius-style deterministic key
generation could plausibly explain those specific keys, validating
candidate seeds against the already-solved puzzles in that series.
Strip the mask out (use the raw derived key directly) to search for an
arbitrary target instead.

## Build

Requires the CUDA toolkit (`nvcc`) and an NVIDIA GPU.

```bash
nvcc -O3 -arch=sm_75 mnemonic_search.cu  -o mnemonic_search
nvcc -O3 -arch=sm_75 armory_search.cu    -o armory_search
nvcc -O3 -arch=sm_75 casascius_search.cu -o casascius_search
```

Adjust `-arch=sm_75` to match your GPU's compute capability
(`sm_75` = Turing, e.g. Tesla T4/RTX 20-series; `sm_86` for Ampere/RTX
30-series; `sm_89` for Ada/RTX 40-series; etc).

## Usage

```bash
./mnemonic_search  <target_hash160_hex_40chars> <puzzle_index> <12|24> [total_threads_per_batch]
./armory_search    <target_hash160_hex_40chars> <puzzle_index> [total_threads_per_batch]
./casascius_search <target_hash160_hex_40chars> <puzzle_index> [total_threads_per_batch]
```

All three run **indefinitely**, launching batches with a new random
seed each time, reporting progress every 5 seconds, until a match is
found or interrupted (`Ctrl+C`).

### Example

```bash
./casascius_search b907c3a2a3b27789dfb509b730dd47703c272868 20
```

(Puzzle #20's real, already-solved `hash160` — useful to confirm the
pipeline runs. **Caution**: see next section before reading anything
into a "match" at low `puzzle_index` values.)

### A statistical trap worth knowing about

The mask limits the *output* to `2^(n-1)` possible values for puzzle
index `n`. For low `n` (e.g. `20`), that's only `524,288` possible
outcomes — small enough that testing hundreds of thousands to
millions of random candidates will produce an apparent "match" by pure
chance, **independent of whether the underlying hypothesis has any
merit**. The expected number of chance matches after `N` attempts is
`N / 2^(n-1)`. Only treat a match as meaningful evidence for `n` large
enough that `2^(n-1)` comfortably exceeds your total attempt count
(e.g. `n ≥ 37` for search volumes up to low billions). All three tools
in this repo will produce "matches" at `n=20` within the first
one-to-a-few-million attempts as pure noise — this was observed and
confirmed during development of all three, and is expected, not a
bug.

## Performance

`mnemonic_search` and `armory_search` use block-level Montgomery batch
modular inversion (one shared inversion per block of threads per
elliptic-curve point needed, instead of one inversion per thread) —
the same technique used by this project's separate `amalia_hier_leaf`
hierarchical-lookup tool, adapted here to a per-attempt random-search
kernel. `casascius_search` needs only one point operation per attempt
(no chained/sequential derivation), so it skips batching and computes
each thread's inversion independently — batching wouldn't meaningfully
help there. Actual throughput depends on your GPU;
`armory_search`'s cost additionally scales with `puzzle_index` due to
its sequential derivation structure.

## Validation

Every primitive was checked against official test vectors (or, for
Casascius, the published reference source directly) in plain C/C++
**before** being ported to CUDA device code, and each full pipeline
was then re-validated on actual GPU hardware — including the
block-level batch-inversion kernel structure specifically (128
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
| **Casascius BAU formula** | **`SHA256("1/teste/1/BITCOIN")`, matches the published formula directly** | **[casascius/Bitcoin-Address-Utility](https://github.com/casascius/Bitcoin-Address-Utility), `Walletgen.cs`** |
| Batched search kernels (128 threads, shared inversion) | all threads converge to the single-thread reference result | this project |

See `validation/` for the individual C/C++ test programs (compile any
of them with `g++ -O2 -x c++ <file>.c -o test && ./test`).

## License

MIT — see source file headers. No warranty; this is research/
educational code.
