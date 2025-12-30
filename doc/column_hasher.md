## Oblivious column hasher

The oblivious column hasher is a primitive used in the Cairo-to-Plonk verifier to hash column values from Merkle tree nodes in a way that is **oblivious to log sizes**. It allows the circuit to hash column values that come from different components with different log sizes, without revealing which log size was used.

### Purpose

During decommitment, column values are included in the Merkle tree nodes at various heights. The heights depend on the log sizes of the components. Some components have dynamic log sizes, but we want the decommitment circuit to be independent of those variations.

The column hasher maintains separate hash accumulators for each possible log size (from `LOG_N_LANES` to `MAX_SEQUENCE_LOG_SIZE`), and uses oblivious selection to update only the accumulator corresponding to the actual log size.

### HashAccumulatorVar

`HashAccumulatorVar` is the basic building block for accumulating M31 field elements into a Poseidon2 hash. It maintains:

- **`buffer: [M31Var; 16]`** - A buffer that accumulates up to 16 M31 elements before hashing
- **`size: [BitVar; 16]`** - A one-hot encoding indicating how many elements are currently in the buffer (0-15)
- **`digest: [QM31Var; 2]`** - The current hash digest (Poseidon2 capacity output)
- **`refresh_counter`** - Tracks when to perform a refresh operation

#### How it works

1. **Update**: Elements are added one at a time. Each element is written to the buffer position indicated by the `size` array (using oblivious selection), then `size` is rotated right.

2. **Refresh**: When 8 elements have been accumulated, a refresh is triggered:
   - The first 8 buffer elements are hashed with the current digest using Poseidon2
   - The buffer is shifted (elements 8-15 move to positions 0-7)
   - The digest and size arrays are updated obliviously based on whether there were at least 8 elements

3. **Finalize**: After all elements are added, a final hash is computed with any remaining buffer elements (padded with zeros for unused positions).

### HashAccumulatorQM31Var

`HashAccumulatorQM31Var` is similar to `HashAccumulatorVar` but works with QM31 elements instead of M31:

- **`buffer: [QM31Var; 4]`** - Smaller buffer (4 QM31 elements = 16 M31 elements worth of data)
- **`size: [BitVar; 4]`** - One-hot encoding for 0-3 elements
- Refreshes after every 2 elements (since 2 QM31 = 8 M31)

This is used for hashing QM31 column values, such as composition polynomial values.

### Compressed variants

Both accumulator types have compressed variants (`HashAccumulatorCompressedVar` and `HashAccumulatorQM31CompressedVar`) that:

- Store only the essential state (size, digest, buffer, compressed_digest)
- Support oblivious selection via `select` method
- Can be decompressed back to full accumulators for updates
- Can be compressed again after updates

The compressed digest is computed by hashing the buffer state with the digest, allowing verification that the compressed state matches the full accumulator.

### ColumnsHasherVar

`ColumnsHasherVar` maintains a map of hash accumulators, one for each possible log size from `LOG_N_LANES` to `MAX_SEQUENCE_LOG_SIZE`. It provides two update methods:

#### Oblivious update (`update`)

```rust
pub fn update(&mut self, log_size: &LogSizeVar, data: &[M31Var])
```

This method updates the accumulator for the log size specified by `log_size`, but does so obliviously:

1. Uses `log_size.bitmap` to obliviously select the correct accumulator from the map
2. Decompresses the selected accumulator
3. Updates it with the new data
4. Compresses it back
5. Obliviously writes it back to the map (only the correct accumulator is updated, others remain unchanged)

This is used for components with variable log sizes, such as opcodes where each opcode component can have different log sizes.

#### Fixed log size update (`update_fixed_log_size`)

```rust
pub fn update_fixed_log_size(&mut self, log_size: u32, data: &[M31Var])
```

This method directly updates the accumulator for a known, fixed log size. It's more efficient when the log size is constant (e.g., for range check components with fixed log sizes).

#### Finalization

The `finalize` method:
1. Decompresses each accumulator
2. Finalizes the hash (handling any remaining buffer elements)
3. Returns a map of `OptionVar<Poseidon2HalfVar>` where `is_some` indicates whether that log size accumulator received any data

### ColumnsHasherQM31Var

`ColumnsHasherQM31Var` is the QM31 variant of `ColumnsHasherVar`, maintaining `HashAccumulatorQM31CompressedVar` instances for each log size. It's used for hashing QM31 column values, such as composition polynomial values.