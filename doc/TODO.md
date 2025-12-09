# TODO

## Incomplete Implementations

### check_claim in cairo-components/recursive/fiat_shamir/src/lib.rs
The `check_claim` implementation is not complete and needs to be finished.

#### Remaining items in check_claim:
- [ ] Implement `accumulate_relation_uses` in the circuit for security
  - Currently commented out (lines 127-133)
  - Need to accumulate relation uses from the claim and verify each count < PRIME
  - This is a security check to ensure relation counts don't overflow
- [ ] Implement `largest_id` check
  - Currently commented out (lines 134-143)
  - Need to verify that the largest memory ID doesn't overflow PRIME
  - Formula: `sum(big_log_sizes.map(|log_size| 1 << log_size)) - 1 + LARGE_MEMORY_VALUE_ID_BASE < PRIME`

## Security - Circuit Implementation

### accumulate_relation_uses in circuit
- [ ] **CRITICAL**: Implement `accumulate_relation_uses` verification in the circuit (cairo-components/recursive/fiat_shamir/src/lib.rs)
  - Currently only implemented in hints (cairo-components/hints/src/fiat_shamir.rs, line 132)
  - Must be implemented in the recursive circuit version for security
  - Need to accumulate all relation uses from the claim and verify that each count < PRIME
  - This prevents relation count overflow attacks
  - Reference implementation exists in hints version but needs to be adapted for circuit constraints

### Lookup sum for public memory
To finish the lookup sum for public memory, need to start with a function that calculates the sum and sum them up, starting with the program, and then the rest.

## Fiat-Shamir Implementation - sampled_values

### Add sampled_values to proof structure
- [x] `sampled_values` field already exists in `StarkProofVar` (cairo-components/recursive/data_structures/src/stark_proof.rs)

### Finish Fiat-Shamir implementation up to sampled_values

#### In hints (cairo-components/hints/src/fiat_shamir.rs)
- [ ] After drawing OODS point (line 343), get mask sample points from components using `components.mask_points(oods_point)`
- [ ] Add composition polynomial mask points to sample_points
- [ ] Mix `sampled_values` from `proof.stark_proof.sampled_values` into the channel (flatten and use appropriate mix method)
- [ ] Draw `after_sampled_values_random_coeff` from channel
- [ ] Store necessary data in `CairoFiatShamirHints` struct for later use (may need to add fields)

#### In recursive (cairo-components/recursive/fiat_shamir/src/lib.rs)
- [ ] After drawing OODS point (line 45), flatten `proof.stark_proof.sampled_values` using `.flatten_cols()`
- [ ] Mix sampled_values into channel in chunks of 2 (use `mix_one_felt` for single, `mix_two_felts` for pairs)
- [ ] Draw `after_sampled_values_random_coeff` from channel using `channel.draw_felts()[0]`

### Goal
Once `sampled_values` is integrated into the Fiat-Shamir flow, this will allow understanding the column structures of the proof, which can guide running `EvalAtRow` over it.