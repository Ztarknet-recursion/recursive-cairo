# TODO

## First Layer Separation and Refactoring

### Overview
Separate the first layer from the rest of the layers. The first layer will have pairs of elements (left and right pairs in each layer). The pairs may or may not each carry a QM31 in that layer.

### Phase 1: Hints Side Implementation ✅ (Completed)
- Tested `FirstLayerHints` struct in `cairo-components/hints/src/folding.rs`
- Incorporated and ensured compatibility with `InnerLayerHints` from `components/hints/src/folding.rs`
- Verified correct folding in hints side

### Phase 2: Constraint System Side Implementation (Current Focus)

1. **Allocate First Layer Data Structure**
   - [ ] Design data structure for first layer with layout independent of log size
   - [ ] Implement allocation in constraint system (`cairo-components/recursive/folding/src/lib.rs`)
   - [ ] Ensure the structure can handle pairs (left and right) flexibly
   - [ ] Support optional QM31 values in pairs
   - [ ] Test allocation with different log sizes

2. **Implement Folding in Constraint System**
   - [ ] Implement parent folding logic in constraint system
   - [ ] Ensure compatibility with hints side implementation (already verified)
   - [ ] Add constraint checks for folding correctness
   - [ ] Test with various proof structures

3. **Integration and Testing**
   - [ ] Integrate first layer with inner layers in constraint system
   - [ ] Ensure end-to-end compatibility between hints and constraint system
   - [ ] Test with proofs that have pairs with and without QM31 values
   - [ ] Verify all folding results match between hints and constraint system

### Related Files
- `cairo-components/hints/src/folding.rs` - First layer hints implementation ✅ (completed)
- `components/hints/src/folding.rs` - Reference implementation with `FirstLayerHints` and `InnerLayerHints`
- `cairo-components/recursive/folding/src/lib.rs` - Constraint system folding (current focus)
- `components/recursive/folding/src/lib.rs` - Reference constraint system folding
- `cairo-components/recursive/fiat_shamir/src/lib.rs` - Fiat-Shamir implementation
- `cairo-components/recursive/data_structures/src/stark_proof.rs` - FRI proof structures
