## Folding protocol

The folding protocol verifies the FRI (Fast Reed-Solomon Interactive) proof by progressively folding the polynomial evaluations until they collapse to a constant. The protocol consists of two distinct phases: the **first layer** and the **inner layers**, which work very differently.

### First layer

The first layer handles FRI answers at all possible log sizes (from `LOG_N_LANES` to `MAX_SEQUENCE_LOG_SIZE`). It provides both the queried values and their siblings from the Merkle tree, which are then used to fold the polynomial.

#### Structure

The first layer Merkle tree has a height determined by the maximum log size of all components. To make the circuit oblivious to this variation, the code assumes a maximum height tree (`MAX_SEQUENCE_LOG_SIZE + log_blowup_factor`) and allows skipping layers that are beyond the actual tree height.

The `PaddedSinglePairMerkleProofVar` structure:
- Contains sibling hashes for all possible heights (padded to maximum)
- Contains column values (self and sibling) at each height, stored as `OptionVar` to indicate presence
- Uses `is_hash_active` to track which layers are actually part of the tree

#### Verification

The first layer verification:
1. Verifies the Merkle proof from the root down to the leaves
2. For each height, checks if columns are present (based on `is_column_present`)
3. Combines tree hashes with column hashes when columns are present
4. Skips layers beyond the actual tree height using `is_hash_active`

#### Folding by y-coordinate

The first layer folds the polynomial by the **y-coordinate**. For each log size `h`, it:

1. Takes the queried value and its sibling from the Merkle proof
2. Computes the folding point by doubling the query position: `point = query_position.double()`
3. Uses the y-coordinate inverse: `y_inv = point.y.inv()`
4. Swaps left/right based on query bit, then folds:
   - `new_left = left + right`
   - `new_right = (left - right) * y_inv`
5. Combines with alpha: `f_prime = new_left + new_right * alpha`

This converts the circle polynomial evaluation into a polynomial evaluation, which can then be further folded in the inner layers.

#### Answer verification

Before folding, the code verifies that the queried values in the Merkle proof match the computed FRI answers:
- For each log size, checks that `proof_column.is_some == answer_column.is_some`
- Verifies that `proof_column.value.0 == answer_column.value` when present

### Inner layers

Inner layers work differently from the first layer. Each inner layer corresponds to a specific log size and has a fixed height. The layers fold the polynomial by the **x-coordinate** and only contain leaf values (no intermediate column values).

#### Structure

Each inner layer uses `LeafOnlySinglePairMerkleProofVar`, which:
- Only contains the leaf column values (self and sibling) at the bottom of the tree
- Contains sibling hashes for all heights above the leaves
- Has a fixed height determined by its log size

#### Oblivious layer skipping

Some inner layers may not be present if the maximum log size of all components is lower than `MAX_SEQUENCE_LOG_SIZE`. To handle this obliviously:

1. The code checks if a real Merkle proof exists for the layer
2. If not present, it creates a **dummy proof** using `LeafOnlySinglePairMerkleProofVar::dummy()`
3. The dummy proof would fail normal verification, but the check is bypassed when `is_layer_present` is false
4. The verification result is conditionally checked: `(verify_result | !is_layer_present) == true`

This allows the circuit to process all possible inner layers without revealing which ones are actually present.

#### Folding by x-coordinate

Each inner layer folds the polynomial by the **x-coordinate**:

1. Takes the leaf values (self and sibling) from the Merkle proof
2. Computes the folding point from the query position: `point = query_position.get_absolute_point()`
3. Uses the x-coordinate inverse: `x_inv = point.x.inv()`
4. Swaps left/right based on query bit, then folds:
   - `new_left = left + right`
   - `new_right = (left - right) * x_inv`
5. Combines with alpha: `new_folded = new_left + new_right * alpha`

The folded result from one layer becomes the input to the next layer.

#### Layer transition

When transitioning from the first layer to inner layers:
- The `f_prime` values computed in the first layer are combined with the folded result
- The formula is: `new_folded = folded * (alpha * alpha) + f_prime`
- This connects the y-coordinate folding (first layer) with the x-coordinate folding (inner layers)

### Final verification

After processing all layers, the final folded result should equal the **last layer constant**:

```rust
folded.equalverify(&proof_var.stark_proof.fri_proof.last_layer_constant);
```

This verifies that the FRI polynomial has been correctly folded down to a constant, which is the core of the FRI protocol.

### Key differences summary

| Aspect | First Layer | Inner Layers |
|--------|-------------|--------------|
| **Log sizes** | All log sizes (LOG_N_LANES to MAX_SEQUENCE_LOG_SIZE) | One log size per layer |
| **Height** | Variable (depends on max log size), padded to maximum | Fixed per layer |
| **Columns** | Columns at multiple heights | Only leaf columns |
| **Folding coordinate** | y-coordinate | x-coordinate |
| **Skipping** | Skip levels beyond actual height | Skip layers that don't exist |
| **Structure** | `PaddedSinglePairMerkleProofVar` | `LeafOnlySinglePairMerkleProofVar` |

### Oblivious properties

Both layers maintain obliviousness to log size variations:

- **First layer**: Assumes maximum height and skips levels beyond the actual tree height
- **Inner layers**: Uses dummy proofs for non-existent layers, with verification bypassed when appropriate
- **Layer presence**: Tracked using `is_layer_present` which is updated based on `max_log_size` comparisons

This design allows a single circuit to handle all possible log size combinations without revealing which specific log sizes are being used.

