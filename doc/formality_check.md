# Cairo proof formality checks

The `check_claim` function in the Cairo-to-Plonk verifier performs the following formality checks on the Cairo proof claim:

## Builtin segments

The only optional builtin that we used is range_check_128, and the remaining builtins are not used. Their segments are empty (start_ptr = end_ptr): `pedersen`, `ecdsa`, `bitwise`, `ec_op`, `keccak`, `poseidon`, `range_check_96`, `add_mod`, `mul_mod`.

### Output builtin segment

The memory segment range must be sensible: start_ptr <= stop_ptr.

### Range check 128 builtin segment

- **Segment start consistency**: `start_ptr == range_check_builtin_segment_start`
- **Segment validity**: `start_ptr <= stop_ptr`
- **Segment bounds**: `stop_ptr <= segment_end` where `segment_end = segment_start + 2^range_check_128_builtin_log_size`

### Initial state checks

- **Initial program counter**: `initial_pc == 1`
- **Initial allocation pointer**: `initial_ap >= 4` (ensures `initial_pc + 2 < initial_ap`)
- **Frame pointer consistency**: `initial_fp == final_fp` (frame pointer must remain constant)
- **Frame pointer initialization**: `initial_fp == initial_ap` (frame pointer equals allocation pointer at start)

### Final state checks

- **Final program counter**: `final_pc == 5`
- **Memory growth**: `initial_ap <= final_ap` (allocation pointer can only grow, never shrink)

### Memory and relation checks

- **Relation uses**: Accumulates all relation uses from the claim and, *during this process*, checks that the relation uses do not overflow the field prime by using [add_assert_no_overflow](primitives/src/m31.rs)
- **Memory ID overflow**: Ensures that the largest memory ID `(2^big_log_size - 1) + LARGE_MEMORY_VALUE_ID_BASE` does not overflow the field prime
