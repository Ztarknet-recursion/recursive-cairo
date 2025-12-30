## Seq franking

Seq franking is a technique used in the Cairo-to-Plonk verifier to enable **oblivious access** to "Seq" preprocessed trace columns. It allows components with variable log sizes to access the correct "Seq" column without making the circuit depend on the specific log size.

Not all components use seq franking. Some components have a fixed log size and therefore access a fixed "Seq" column. In this case, seq franking is not necessary.

### Purpose

Some Cairo components have log sizes that are not fixed. These components use "Seq" preprocessed trace columns, but the specific "Seq" column they need depends on their log size. For example, a component with log size 20 needs `seq_20`, while a component with log size 18 needs `seq_18`.

Seq franking makes this access **oblivious**: the circuit cannot determine which specific "Seq" column is being accessed, while still ensuring the correct column is used for the component's actual log size.

### How it works

When `seq_franking` is enabled and a component requests a "Seq" preprocessed column (identified by column IDs starting with `"seq_"`), the `PointEvaluatorVar` performs the following:

1. **Oblivious selection**: For each possible log size `i` from `LOG_N_LANES` to `MAX_SEQUENCE_LOG_SIZE`:
   - Retrieves the corresponding bit from the component's `log_size.bitmap` (which indicates if the component's log size equals `i`)
   - Uses `QM31Var::select_add` to accumulate the preprocessed mask value from the `seq_i` column, but only if the bit is true
   - Verifies that if the bit is true, the corresponding preprocessed trace must be present (enforced by the constraint `(bit & is_preprocessed_trace_present) | !bit = 1`)

2. **Result**: The accumulated result is the mask value from the correct "Seq" column (the one matching the component's actual log size), but the circuit cannot determine which column was selected.

### Components using seq franking

The following components use seq franking (with `seq_franking = true`):

- `blake_compress_opcode` - uses seq columns based on its log size
- `range_check_builtin_bits_128` - uses seq columns based on the builtin's log size
- `memory_address_to_id` - uses seq columns based on its log size
- `memory_id_to_big` - uses seq columns based on its log size
- `memory_id_to_small` - uses seq columns based on its log size

All other components use `seq_franking = false` and access preprocessed columns directly without oblivious selection.