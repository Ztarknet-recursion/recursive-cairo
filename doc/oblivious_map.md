## LogSizeVar and ObliviousMapVar

This document describes `LogSizeVar` and `ObliviousMapVar`, two primitives used to make circuit computations oblivious to the log sizes of Cairo components.

### LogSizeVar

`LogSizeVar` represents a log size value with multiple representations.

`LogSizeVar` contains four fields:

- **`bits: BitIntVar<5>`** - The log size represented as a 5-bit integer. This allows the log size to range from 0 to 31.
- **`m31: M31Var`** - The log size as an M31 field element, derived from the bits representation.
- **`pow2: M31Var`** - The value 2^log_size, computed as `m31.exp2()`. This is useful for operations that need the actual size rather than the log size (e.g. dividing the cumulative checksum by the pow2, tallying the relation uses).
- **`bitmap: IndexMap<u32, BitVar>`** - A bitmap that indicates which specific log size value this represents. For each possible log size `k` from `LOG_N_LANES` to `MAX_SEQUENCE_LOG_SIZE`, the bitmap contains a `BitVar` that is `true` if the log size equals `k`, and `false` otherwise.

The bitmap is constructed by comparing the `m31` field element against each possible log size value in the range. This bitmap is the key mechanism that enables oblivious selection in `ObliviousMapVar`.

### ObliviousMapVar

`ObliviousMapVar<T>` is a map from log size keys (u32) to values of type `T`, where `T` must implement the `SelectVar` trait (an internal trait that enables oblivious selection for various types). It enables **oblivious selection** of a value based on a `LogSizeVar` without revealing which key was selected.

#### How it works

The `select` method takes a `LogSizeVar` as input and returns the value from the map corresponding to that log size. The selection is performed obliviously using the bitmap from the `LogSizeVar`:

1. For each `(key, value)` pair in the map, it retrieves the corresponding bit from the `LogSizeVar`'s bitmap.
2. It uses the `SelectVar` trait methods to accumulate values: only the value whose key matches the log size (where the bitmap bit is `true`) contributes to the final result, while all other values contribute zero.
3. The result is the selected value, but the circuit cannot determine which key was used.
