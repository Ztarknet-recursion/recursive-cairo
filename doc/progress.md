## Progress (ongoing)

### “Components” (STWO `Components`) construction assumptions

The hints code constructs a STWO `Components` object from Cairo AIR components:

- `component_generator.components()` is used as the canonical list of AIR components.
- `Components { components: ..., n_preprocessed_columns }` is then used to:
  - Derive `composition_log_size` (via `composition_log_degree_bound()`).
  - Derive mask sample points (via `mask_points(oods_point)`), with an extra final “composition mask” layer appended manually.

## Main challenge: supporting multiple log sizes in a single circuit

In production, different Cairo components (and different proof instances) may have different `log_size`s. The goal is a **single recursive circuit** that can verify proofs across that variability, rather than compiling one circuit per shape.

The key constraint is that the circuit must work for `log_size` in a known range:

- **Lower bound**: `LOG_N_LANES` (SIMD lane lower bound).
- **Upper bound**: `MAX_SEQUENCE_LOG_SIZE` (upper bound baked into the preprocessed trace).

The core technique used throughout `cairo-components/recursive/` is:

- Allocate for the **maximum** shape (up to `MAX_SEQUENCE_LOG_SIZE`), then
- Use **oblivious / conditional selection** (bit-controlled muxes) to “activate” only the parts that are semantically present for the current proof instance.

### Common patterns used in `cairo-components/recursive/`

- **Optional values (`OptionVar`)**
  - Used when some values may not exist for smaller log sizes (presence is carried by a bit, value is still allocated).
  - Example: preprocessed trace sampled-values are exposed via `OptionVar<QM31Var>` in `cairo-components/recursive/answer/src/data_structures/preprocessed.rs`.

### Fiat–Shamir impact: skipping absent sampled values / commitments

Two concrete issues that require “variable-log-size aware” Fiat–Shamir:

- **Preprocessed sampled values may not be present**
  - `StarkProofVar` encodes the preprocessed round (`sampled_values[0]`) so that each column is either:
    - A single evaluation (present), or
    - An empty column (absent), represented by a dummy zero plus a `false` presence bit.
  - See: `cairo-components/recursive/data_structures/src/stark_proof.rs` (`is_preprocessed_trace_present`).
  - The recursive Fiat–Shamir then hashes sampled values into the channel using a conditional mixer:
    - See: `cairo-components/recursive/fiat_shamir/src/lib.rs` (`ConditionalChannelMixer::mix(..., is_preprocessed_trace_present)`).

- **FRI inner layers depend on the maximal log size**
  - The recursive Fiat–Shamir loops over all possible inner layers up to `MAX_SEQUENCE_LOG_SIZE`, but conditionally “skips” layers above the current `max_log_size` by restoring the previous digest using `QM31Var::select`.
  - See: `cairo-components/recursive/fiat_shamir/src/lib.rs` (the `num_layers_to_skip` / `skip` logic).

Additionally, query generation is made shape-stable by masking query bits above the effective `query_log_size`:

- See: `cairo-components/recursive/fiat_shamir/src/lib.rs` (builds a `mask: Vec<BitVar>` and ANDs it into query bit-vectors).

### Decommitment impact: computing column hashes without fixing component log sizes

Merkle decommitment verification needs per-layer hashing that depends on whether a “column hash” exists at that layer. Because log sizes vary, the circuit can’t hardcode a single per-layer “has column” schedule.

Two key building blocks are used:

- **Oblivious per-log-size column hashing**
  - `cairo-components/recursive/decommitment/src/utils.rs` defines `ColumnsHasherVar` / `ColumnsHasherQM31Var`, which maintain a hash accumulator for every candidate log size in `[LOG_N_LANES..=MAX_SEQUENCE_LOG_SIZE]`.
  - The circuit selects which accumulator to update using `log_size.bitmap`, updates it, and writes it back with conditional selection—so the constraint system doesn’t depend on the actual `log_size`.
  - Finalization returns `IndexMap<usize, OptionVar<Poseidon2HalfVar>>`, i.e. each candidate hash is accompanied by an `is_some` bit.

- **Conditional incorporation of column hashes during Merkle path verification**
  - `QueryDecommitmentProofVar::verify` (`cairo-components/recursive/decommitment/src/data_structures.rs`) computes `expected_hash` bottom-up, and conditionally chooses:
    - “hash-without-column” vs “hash-with-column” using `OptionVar.is_some`, and
    - Whether a layer is constrained at all using `max_tree_log_size` / `max_included_log_size` comparisons.

This is the same overarching principle as Fiat–Shamir’s “skip absent sampled values”: allocate the maximum structure, then use bits to ensure only the semantically-present parts constrain the proof.

## What’s implemented (high level)

- **Fiat–Shamir transcript replay for Cairo proofs**: `cairo-components/hints/src/fiat_shamir.rs`
  - Replays transcript mixing of claim/public memory + commitments, draws interaction elements, commits interaction trace, commits composition, samples OODS, derives mask points and FRI query positions.
- **Composition OODS evaluation cross-check**: `cairo-components/hints/src/composition.rs`
  - Evaluates constraint quotients for the selected component set and checks it matches `Components::eval_composition_polynomial_at_point(...)`.

## Open items / next steps

- Relax “component inventory” assumptions (builtins/opcodes) to support more general Cairo proofs.
- Remove debug prints from hints (`println!`) once stabilized, or gate them behind a feature flag.
- Implement/port folding + decommitment logic for Cairo proofs on the hints side (see `doc/TODO.md`).

