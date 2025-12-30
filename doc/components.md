## List of components in Cairo

This markdown lists the components in Cairo that need to be verified in Stwo-Plonk and some discussions about them.

- [Opcodes](#opcodes)
- [Verify Instruction](#verify-instruction)
- [Blake Context](#blake-context)
- [Range Check Builtin Bits 128](#range-check-builtin-bits-128)
- [Memory](#memory)
- [Range Checks](#range-checks)
- [Verify Bitwise](#verify-bitwise)

## Opcodes

- `add`
- `add_small`
- `add_ap`
- `assert_eq`
- `assert_eq_imm`
- `assert_eq_double_deref`
- `blake` (requires seq franking)
- `call`
- `call_rel_imm`
- `jnz`
- `jnz_taken`
- `jump_rel`
- `jump_rel_imm`
- `mul`
- `mul_small`
- `qm31`
- `ret`

## Verify Instruction

- `verify_instruction`

## Blake Context

- `blake_round`
- `blake_g`
- `blake_sigma`
- `triple_xor_32`
- `verify_bitwise_xor_12` (fixed log size)

## Range Check Builtin Bits 128

- `range_check_builtin_bits_128` (requires seq franking)

## Memory

- `memory_address_to_id` (requires seq franking)
- `memory_id_to_big` (requires seq franking)
- `memory_id_to_small` (requires seq franking)

## Range Checks

All have fixed log sizes and do not require seq franking.

- `range_check_6`
- `range_check_8`
- `range_check_11`
- `range_check_12`
- `range_check_18`
- `range_check_18_b`
- `range_check_20`
- `range_check_20_b`
- `range_check_20_c`
- `range_check_20_d`
- `range_check_20_e`
- `range_check_20_f`
- `range_check_20_g`
- `range_check_20_h`
- `range_check_4_3`
- `range_check_4_4`
- `range_check_5_4`
- `range_check_9_9`
- `range_check_9_9_b`
- `range_check_9_9_c`
- `range_check_9_9_d`
- `range_check_9_9_e`
- `range_check_9_9_f`
- `range_check_9_9_g`
- `range_check_9_9_h`
- `range_check_7_2_5`
- `range_check_3_6_6_3`
- `range_check_4_4_4_4`
- `range_check_3_3_3_3_3`

## Verify Bitwise

All have fixed log sizes and do not require seq franking.

- `verify_bitwise_xor_4`
- `verify_bitwise_xor_7`
- `verify_bitwise_xor_8`
- `verify_bitwise_xor_8_b`
- `verify_bitwise_xor_9`