Generated using AI
In this CTF partocipated as a member of Hidden Investigations

# tiles + ai (rev) - Full Beginner-Friendly Solution

## Challenge Summary

This challenge is a reverse engineering problem where a stripped, statically linked ELF asks for three inputs (`0>`, `1>`, `2>`). The binary uses Intel AMX tile instructions, and it refuses to run on CPUs that do not have AMX permissions enabled.

At the end, if all three rounds pass internal checks, the program reads and prints `flag.txt`.

---

## Final Solved Outputs

Use these three lines in order:

1. `01e2e210f3f3f3010101`
2. `01f320e201`
3. `0120a2a2c231f2f2f2109393019311e320b211e3e300e31010923092921111c311d230e23030d310f3209201e2e210b3b3b30101`

Remote result:

`bctf{in_the_matrix_straight_up_multiplying_it_ec3428a06}`

---

## What Happened, In Plain English

The binary is basically a custom state machine driven by pairs of characters.

- Every 2 characters are interpreted as one symbol.
- Each symbol transforms an internal state using AMX matrix/tile operations.
- After processing your whole line, the state must satisfy strict conditions.
- This is repeated for 3 rounds.
- If all rounds pass, it opens `flag.txt`.

The hard part is that the math engine uses AMX instructions, so common disassemblers may show `(bad)` instructions unless you use a decoder that supports AMX.

---

## Step-by-Step Solve

## 1) Initial triage

You can quickly verify binary type:

```bash
file chall
```

Result (important parts):

- ELF 64-bit
- statically linked
- stripped

Running it on a normal machine gave:

`Cannot run on this CPU`

That already tells us there is a CPU feature gate.

---

## 2) Find why it says "Cannot run on this CPU"

From disassembly around `0x4011a2`:

- It calls helper `0x403942` twice.
- Arguments correspond to Linux `arch_prctl` syscall (`0x9e`) with code `0x1023` (`ARCH_REQ_XCOMP_PERM`).
- Requested xstate components are `0x12` (18) and `0x11` (17).

Those are AMX-related xstate permissions:

- `17` = AMX tile configuration state
- `18` = AMX tile data state

If either request fails, it jumps to print `Cannot run on this CPU` and returns.

This is exactly why the challenge note references Intel SDE and a Sapphire Rapids preset.

---

## 3) Decode AMX instructions correctly

Normal `objdump` often failed to decode AMX instructions and showed `(bad)` for important parts. That is dangerous because it hides real behavior.

To avoid guessing, a modern decoder (`iced-x86`) was used to decode raw bytes. That recovered real instructions such as:

- `ldtilecfg`
- `tileloadd`
- `tdpbssd`
- `tilestored`
- `tilerelease`

Once these decode correctly, the state transition logic becomes reconstructable.

---

## 4) Recover input format exactly

From parser logic around `0x401366` onward:

- Input is processed in 2-character chunks.
- First char is parsed as hex-like nibble (`0-9`, `a-f`, `A-F`) -> value `x` in `[0..15]`.
- Second char is parsed similarly, but then checked `<= 3` -> value `y` in `[0..3]`.

So each token is one of 64 possible symbols `(x, y)`.

Examples:

- `a2` means `x=10`, `y=2`
- `f3` means `x=15`, `y=3`

---

## 5) Recover constant tables from binary

Static tables are embedded in `chall`:

- `A` table at `0x409000`, size `0x1000`
- `B` table at `0x40a000`, size `0x1000`
- `C` table at `0x40b000`, size `0x4800`
- Round initial states `R` at `0x40f800`, size `0x900`

State per round is `0x300` bytes, naturally split into 3 chunks of `0x100` bytes (`16x16`) each.

---

## 6) Reconstruct transition function

For each input token `(x, y)`, state is updated with AMX dot-product operations.

At high level:

1. Select `h = x >> 3` (top bit region split of x).
2. For each output chunk index `rbp` in `{0,1,2}`:
   - Start accumulator matrix `acc = 0`.
   - For each source chunk `rcx` in `{0,1,2}`:
     - Multiply source chunk with `A[x]` using `tdpbssd`.
     - Truncate `int32 -> byte` (keep low 8 bits, like `vpmovdb`).
     - Repack bytes into tile layout expected by later AMX multiply.
     - Accumulate with `C[h][y][rbp][rcx]` using `tdpbssd`.
   - Add another term from current chunk and `B[x]` using `tdpbssd`.
   - Truncate to bytes to form next state chunk.

This is exactly what the solver script implements.

---

## 7) Recover acceptance checks

After processing all tokens in a round, checks at `0x401b16` onward enforce:

1. In first `0x240` bytes (36 blocks of 16 bytes):
   - Each byte interpreted as signed int8 must be non-negative.
   - Sum of each 16-byte block must be `< 2`.

2. One special byte must be exactly 1:
   - state offset `0x110` (absolute `0x412380` in runtime memory)

Only if checks pass does the round continue.

After 3 successful rounds, it opens `flag.txt` and prints its content.

Important detail:

- There is a fake local fallback string `flag{fake_flag}`.
- If file open/read fails, program can print that fake value.
- Real solve is validated against remote service that has real `flag.txt`.

---

## 8) Search strategy (why BFS)

Bruteforcing all strings blindly is impossible because branching factor is 64 per symbol.

The solve uses BFS over states:

- Node = full 0x300-byte state.
- Edge = apply one token `(x, y)`.
- Start node = per-round initial state from table `R[round]`.
- Goal = acceptance predicate above.

A key optimization: prune states that already violate signed/sum constraints (`valid(state)`).

Why BFS:

- Finds shortest valid token sequence naturally.
- Deterministic and easy to verify.

---

## 9) Implementation used

A reproducible solver was written in:

- `solve_tiles_ai.py`

Run:

```bash
python3 solve_tiles_ai.py
```

It prints the three input lines directly.

---

## Why this challenge is interesting

This is a good example of modern RE where:

- CPU features are part of the protection layer.
- Correct instruction decoding matters (AMX support required).
- Final exploit is not patching, but exact algorithm reconstruction.
- A mathematically faithful emulator plus graph search yields deterministic solve.

---

## Beginner Glossary (Detailed)

## Reverse Engineering

Understanding how a compiled program works without original source code, by reading assembly, decompiled code, and runtime behavior.

## ELF

Executable and Linkable Format. Standard executable format on Linux.

## Statically Linked

Most library code is inside the executable itself, not loaded from system shared libraries at runtime. This often makes binaries larger but self-contained.

## Stripped Binary

Symbol names (function names, debug info) are removed. You see raw addresses instead of friendly names.

## Disassembly

Turning machine code bytes into assembly instructions.

## Decompilation

Trying to reconstruct C-like pseudocode from assembly. Useful, but imperfect.

## Syscall

A direct request from user program to kernel (OS) for privileged services.

## arch_prctl

A Linux syscall interface for architecture-specific controls on x86_64.

## XSTATE

Extended CPU register state managed by OS save/restore logic (SSE/AVX/AMX states, etc.).

## ARCH_REQ_XCOMP_PERM

A request to Linux kernel to allow access to specific xstate components for a process.

## AMX (Advanced Matrix Extensions)

Intel instruction set extension for high-throughput matrix/tensor-style operations.

## Tile Registers (TMM)

Special AMX matrix registers (`tmm0...tmm7`) storing 2D blocks of data.

## ldtilecfg

Loads tile shape/configuration from memory. Without valid config, tile instructions are undefined/invalid.

## tileloadd / tilestored

Load/store tile data between memory and tile registers.

## tdpbssd

AMX integer dot-product instruction. Multiplies signed bytes in groups and accumulates into int32 outputs.

## tilerelease

Releases tile state resources after tile usage.

## Signed vs Unsigned Byte

- Unsigned byte: 0..255
- Signed byte: -128..127

Same raw byte can mean different value depending on interpretation.

## Truncation (int32 -> byte)

Keeping only the lowest 8 bits of a larger integer. Equivalent to modulo 256 on non-negative values.

## State Machine

A system where current internal state plus input symbol determines next state.

## Lookup Table

Precomputed constants stored in memory, used to transform data quickly instead of recomputing formulas.

## BFS (Breadth-First Search)

Graph search exploring states layer by layer by distance from start. Finds shortest path if each step has equal cost.

## Pruning

Skipping branches that cannot lead to success, to reduce search time.

## Emulator (Behavioral Model)

A reimplementation of target logic in another language (here Python), aiming to match behavior exactly.

## Fake Flag

A decoy flag-like string included to mislead local-only solvers. Real validation is remote.

## Intel SDE

Software Development Emulator from Intel. Emulates new CPU instruction features even if your host CPU does not support them.

---

## Notes for beginners doing similar challenges

1. Always verify parser rules exactly before solving math.
2. If decoder says `(bad)`, do not trust partial disassembly.
3. Prefer faithful emulation over speculative patching.
4. Verify remotely when challenge has network endpoint.
5. Treat any embedded `flag{...}` string as suspicious until validated.
