# TODO

## Incomplete Implementations

### Lookup sum for public memory
To finish the lookup sum for public memory, need to start with a function that calculates the sum and sum them up, starting with the program, and then the rest.

## FRI Verifier - Degree Bounds

### Check degree bounds
- [ ] Get the degree bounds and check what the degree bounds are
  - This impacts whether we need to implement `FriVerifier` in a way that works with multiple degree bounds
  - Need to understand if different parts of the proof use different degree bounds
  - Determine if a single-degree or multi-degree FRI verifier implementation is required

## Composition Logic

### Move and complete composition calculation
- [ ] Move the composition logic to another hint rust file
- [ ] Finish the rest of the composition calculation
- [ ] Compare the value with the one from Stwo

## Cairo Components Analysis

### Analyze log_size dependencies
- [ ] Analyze how many cairo components may be dependent on log_size and make a list