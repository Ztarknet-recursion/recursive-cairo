# TODO

## Incomplete Implementations

### check_claim in cairo-components/recursive/fiat_shamir/src/lib.rs
The `check_claim` implementation is not complete and needs to be finished.

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