use cairo_air::components;
use circle_plonk_dsl_constraint_system::{var::Var, ConstraintSystemRef};
use circle_plonk_dsl_primitives::{option::OptionVar, BitVar, QM31Var};
use itertools::Itertools;

pub struct PreprocessedTraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub seq_25: OptionVar<QM31Var>,
    pub seq_24: OptionVar<QM31Var>,
    pub seq_23: OptionVar<QM31Var>,
    pub seq_22: OptionVar<QM31Var>,
    pub seq_21: OptionVar<QM31Var>,
    pub seq_20: QM31Var, /* used by range check 20, 20b, 20c, 20d, 20e, 20f, 20g, 20h */
    pub bitwise_xor_10_0: QM31Var,
    pub bitwise_xor_10_1: QM31Var,
    pub bitwise_xor_10_2: QM31Var,
    pub seq_19: OptionVar<QM31Var>,
    pub seq_18: QM31Var, /* used by range check 18, 18b */
    pub bitwise_xor_9_0: QM31Var,
    pub bitwise_xor_9_1: QM31Var,
    pub bitwise_xor_9_2: QM31Var,
    pub range_check_9_9_column_0: QM31Var,
    pub range_check_9_9_column_1: QM31Var,
    pub range_check_3_6_6_3_column_0: QM31Var,
    pub range_check_3_6_6_3_column_1: QM31Var,
    pub range_check_3_6_6_3_column_2: QM31Var,
    pub range_check_3_6_6_3_column_3: QM31Var,
    pub seq_17: OptionVar<QM31Var>,
    pub seq_16: OptionVar<QM31Var>,
    pub bitwise_xor_8_0: QM31Var,
    pub bitwise_xor_8_1: QM31Var,
    pub bitwise_xor_8_2: QM31Var,
    pub range_check_4_4_4_4_column_0: QM31Var,
    pub range_check_4_4_4_4_column_1: QM31Var,
    pub range_check_4_4_4_4_column_2: QM31Var,
    pub range_check_4_4_4_4_column_3: QM31Var,
    pub seq_15: OptionVar<QM31Var>,
    pub range_check_3_3_3_3_3_column_0: QM31Var,
    pub range_check_3_3_3_3_3_column_1: QM31Var,
    pub range_check_3_3_3_3_3_column_2: QM31Var,
    pub range_check_3_3_3_3_3_column_3: QM31Var,
    pub range_check_3_3_3_3_3_column_4: QM31Var,
    pub seq_14: OptionVar<QM31Var>,
    pub bitwise_xor_7_0: QM31Var,
    pub bitwise_xor_7_1: QM31Var,
    pub bitwise_xor_7_2: QM31Var,
    pub range_check_7_2_5_column_0: QM31Var,
    pub range_check_7_2_5_column_1: QM31Var,
    pub range_check_7_2_5_column_2: QM31Var,
    pub seq_13: OptionVar<QM31Var>,
    pub seq_12: QM31Var, /* used by range check 12 */
    pub seq_11: QM31Var, /* used by range check 11 */
    pub seq_10: OptionVar<QM31Var>,
    pub seq_9: OptionVar<QM31Var>,
    pub range_check_5_4_column_0: QM31Var,
    pub range_check_5_4_column_1: QM31Var,
    pub seq_8: QM31Var, /* used by range check 8 */
    pub bitwise_xor_4_0: QM31Var,
    pub bitwise_xor_4_1: QM31Var,
    pub bitwise_xor_4_2: QM31Var,
    pub range_check_4_4_column_0: QM31Var,
    pub range_check_4_4_column_1: QM31Var,
    pub seq_7: OptionVar<QM31Var>,
    pub range_check_4_3_column_0: QM31Var,
    pub range_check_4_3_column_1: QM31Var,
    pub seq_6: QM31Var, /* used by range check 6 */
    pub seq_5: OptionVar<QM31Var>,
    pub seq_4: QM31Var, /* used by blake_round_sigma */
    pub blake_sigma_0: QM31Var,
    pub blake_sigma_1: QM31Var,
    pub blake_sigma_2: QM31Var,
    pub blake_sigma_3: QM31Var,
    pub blake_sigma_4: QM31Var,
    pub blake_sigma_5: QM31Var,
    pub blake_sigma_6: QM31Var,
    pub blake_sigma_7: QM31Var,
    pub blake_sigma_8: QM31Var,
    pub blake_sigma_9: QM31Var,
    pub blake_sigma_10: QM31Var,
    pub blake_sigma_11: QM31Var,
    pub blake_sigma_12: QM31Var,
    pub blake_sigma_13: QM31Var,
    pub blake_sigma_14: QM31Var,
    pub blake_sigma_15: QM31Var,
}

impl PreprocessedTraceSampleResultVar {
    pub fn new(
        sampled_values: &Vec<Vec<QM31Var>>,
        is_preprocessed_trace_present: &Vec<BitVar>,
    ) -> Self {
        let sampled_values = sampled_values.iter().map(|v| &v[0]).collect_vec();

        Self {
            cs: is_preprocessed_trace_present[0].cs(),
            seq_25: OptionVar::new(
                is_preprocessed_trace_present[0].clone(),
                sampled_values[0].clone(),
            ),
            seq_24: OptionVar::new(
                is_preprocessed_trace_present[1].clone(),
                sampled_values[1].clone(),
            ),
            seq_23: OptionVar::new(
                is_preprocessed_trace_present[2].clone(),
                sampled_values[2].clone(),
            ),
            seq_22: OptionVar::new(
                is_preprocessed_trace_present[3].clone(),
                sampled_values[3].clone(),
            ),
            seq_21: OptionVar::new(
                is_preprocessed_trace_present[4].clone(),
                sampled_values[4].clone(),
            ),
            seq_20: sampled_values[5].clone(),
            bitwise_xor_10_0: sampled_values[6].clone(),
            bitwise_xor_10_1: sampled_values[7].clone(),
            bitwise_xor_10_2: sampled_values[8].clone(),
            seq_19: OptionVar::new(
                is_preprocessed_trace_present[9].clone(),
                sampled_values[9].clone(),
            ),
            seq_18: sampled_values[10].clone(),
            bitwise_xor_9_0: sampled_values[11].clone(),
            bitwise_xor_9_1: sampled_values[12].clone(),
            bitwise_xor_9_2: sampled_values[13].clone(),
            range_check_9_9_column_0: sampled_values[14].clone(),
            range_check_9_9_column_1: sampled_values[15].clone(),
            range_check_3_6_6_3_column_0: sampled_values[16].clone(),
            range_check_3_6_6_3_column_1: sampled_values[17].clone(),
            range_check_3_6_6_3_column_2: sampled_values[18].clone(),
            range_check_3_6_6_3_column_3: sampled_values[19].clone(),
            seq_17: OptionVar::new(
                is_preprocessed_trace_present[20].clone(),
                sampled_values[20].clone(),
            ),
            seq_16: OptionVar::new(
                is_preprocessed_trace_present[21].clone(),
                sampled_values[21].clone(),
            ),
            bitwise_xor_8_0: sampled_values[22].clone(),
            bitwise_xor_8_1: sampled_values[23].clone(),
            bitwise_xor_8_2: sampled_values[24].clone(),
            range_check_4_4_4_4_column_0: sampled_values[25].clone(),
            range_check_4_4_4_4_column_1: sampled_values[26].clone(),
            range_check_4_4_4_4_column_2: sampled_values[27].clone(),
            range_check_4_4_4_4_column_3: sampled_values[28].clone(),
            seq_15: OptionVar::new(
                is_preprocessed_trace_present[29].clone(),
                sampled_values[29].clone(),
            ),
            range_check_3_3_3_3_3_column_0: sampled_values[30].clone(),
            range_check_3_3_3_3_3_column_1: sampled_values[31].clone(),
            range_check_3_3_3_3_3_column_2: sampled_values[32].clone(),
            range_check_3_3_3_3_3_column_3: sampled_values[33].clone(),
            range_check_3_3_3_3_3_column_4: sampled_values[34].clone(),
            seq_14: OptionVar::new(
                is_preprocessed_trace_present[35].clone(),
                sampled_values[35].clone(),
            ),
            bitwise_xor_7_0: sampled_values[36].clone(),
            bitwise_xor_7_1: sampled_values[37].clone(),
            bitwise_xor_7_2: sampled_values[38].clone(),
            range_check_7_2_5_column_0: sampled_values[39].clone(),
            range_check_7_2_5_column_1: sampled_values[40].clone(),
            range_check_7_2_5_column_2: sampled_values[41].clone(),
            seq_13: OptionVar::new(
                is_preprocessed_trace_present[42].clone(),
                sampled_values[42].clone(),
            ),
            seq_12: sampled_values[43].clone(),
            seq_11: sampled_values[44].clone(),
            seq_10: OptionVar::new(
                is_preprocessed_trace_present[45].clone(),
                sampled_values[45].clone(),
            ),
            seq_9: OptionVar::new(
                is_preprocessed_trace_present[46].clone(),
                sampled_values[46].clone(),
            ),
            range_check_5_4_column_0: sampled_values[47].clone(),
            range_check_5_4_column_1: sampled_values[48].clone(),
            seq_8: sampled_values[49].clone(),
            bitwise_xor_4_0: sampled_values[50].clone(),
            bitwise_xor_4_1: sampled_values[51].clone(),
            bitwise_xor_4_2: sampled_values[52].clone(),
            range_check_4_4_column_0: sampled_values[53].clone(),
            range_check_4_4_column_1: sampled_values[54].clone(),
            seq_7: OptionVar::new(
                is_preprocessed_trace_present[55].clone(),
                sampled_values[55].clone(),
            ),
            range_check_4_3_column_0: sampled_values[56].clone(),
            range_check_4_3_column_1: sampled_values[57].clone(),
            seq_6: sampled_values[58].clone(),
            seq_5: OptionVar::new(
                is_preprocessed_trace_present[89].clone(),
                sampled_values[89].clone(),
            ),
            seq_4: sampled_values[90].clone(),
            blake_sigma_0: sampled_values[91].clone(),
            blake_sigma_1: sampled_values[92].clone(),
            blake_sigma_2: sampled_values[93].clone(),
            blake_sigma_3: sampled_values[94].clone(),
            blake_sigma_4: sampled_values[95].clone(),
            blake_sigma_5: sampled_values[96].clone(),
            blake_sigma_6: sampled_values[97].clone(),
            blake_sigma_7: sampled_values[98].clone(),
            blake_sigma_8: sampled_values[99].clone(),
            blake_sigma_9: sampled_values[100].clone(),
            blake_sigma_10: sampled_values[101].clone(),
            blake_sigma_11: sampled_values[102].clone(),
            blake_sigma_12: sampled_values[103].clone(),
            blake_sigma_13: sampled_values[104].clone(),
            blake_sigma_14: sampled_values[105].clone(),
            blake_sigma_15: sampled_values[106].clone(),
        }
    }
}

pub struct TraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesTraceSampleResultVar,
    pub verify_instruction: [QM31Var; components::verify_instruction::N_TRACE_COLUMNS],
    pub blake: BlakeTraceSampleResultVar,
    pub range_check_128_builtin:
        [QM31Var; components::range_check_builtin_bits_128::N_TRACE_COLUMNS],
    pub memory_address_to_id: [QM31Var; components::memory_address_to_id::N_TRACE_COLUMNS],
    pub memory_id_to_big_big: [QM31Var; components::memory_id_to_big::BIG_N_COLUMNS],
    pub memory_id_to_big_small: [QM31Var; components::memory_id_to_big::SMALL_N_COLUMNS],
    pub range_checks: RangeChecksTraceSampleResultVar,
    pub verify_bitwise: VerifyBitwiseTraceSampleResultVar,
}

/// Helper function to extract a fixed-size array from a slice
fn extract_array<const N: usize>(slice: &[&QM31Var], offset: &mut usize) -> [QM31Var; N] {
    let arr = std::array::from_fn(|i| slice[*offset + i].clone());
    *offset += N;
    arr
}

impl TraceSampleResultVar {
    pub fn new(cs: &ConstraintSystemRef, sampled_values: &Vec<Vec<QM31Var>>) -> Self {
        let sampled_values: Vec<&QM31Var> = sampled_values.iter().map(|v| &v[0]).collect();
        let mut offset = 0;

        // Allocate in the exact order as defined in TraceSampleResultVar
        let opcodes = allocate_opcodes(cs, &sampled_values, &mut offset);
        let verify_instruction = extract_array::<{ components::verify_instruction::N_TRACE_COLUMNS }>(
            &sampled_values,
            &mut offset,
        );
        let blake = allocate_blake(cs, &sampled_values, &mut offset);
        let range_check_128_builtin = extract_array::<
            { components::range_check_builtin_bits_128::N_TRACE_COLUMNS },
        >(&sampled_values, &mut offset);
        let memory_address_to_id = extract_array::<
            { components::memory_address_to_id::N_TRACE_COLUMNS },
        >(&sampled_values, &mut offset);
        let memory_id_to_big_big = extract_array::<{ components::memory_id_to_big::BIG_N_COLUMNS }>(
            &sampled_values,
            &mut offset,
        );
        let memory_id_to_big_small = extract_array::<
            { components::memory_id_to_big::SMALL_N_COLUMNS },
        >(&sampled_values, &mut offset);
        let range_checks = allocate_range_checks(cs, &sampled_values, &mut offset);
        let verify_bitwise = allocate_verify_bitwise(cs, &sampled_values, &mut offset);

        assert_eq!(
            offset,
            sampled_values.len(),
            "Not all sampled values were consumed"
        );

        Self {
            cs: cs.clone(),
            opcodes,
            verify_instruction,
            blake,
            range_check_128_builtin,
            memory_address_to_id,
            memory_id_to_big_big,
            memory_id_to_big_small,
            range_checks,
            verify_bitwise,
        }
    }
}

/// Allocate OpcodesTraceSampleResultVar from slice
fn allocate_opcodes(
    cs: &ConstraintSystemRef,
    slice: &[&QM31Var],
    offset: &mut usize,
) -> OpcodesTraceSampleResultVar {
    OpcodesTraceSampleResultVar {
        cs: cs.clone(),
        add: extract_array::<{ components::add_opcode::N_TRACE_COLUMNS }>(slice, offset),
        add_small: extract_array::<{ components::add_opcode_small::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        add_ap: extract_array::<{ components::add_ap_opcode::N_TRACE_COLUMNS }>(slice, offset),
        assert_eq: extract_array::<{ components::assert_eq_opcode::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        assert_eq_imm: extract_array::<{ components::assert_eq_opcode_imm::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        assert_eq_double_deref: extract_array::<
            { components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS },
        >(slice, offset),
        blake: extract_array::<{ components::blake_compress_opcode::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        call: extract_array::<{ components::call_opcode_abs::N_TRACE_COLUMNS }>(slice, offset),
        call_rel_imm: extract_array::<{ components::call_opcode_rel_imm::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        jnz: extract_array::<{ components::jnz_opcode_non_taken::N_TRACE_COLUMNS }>(slice, offset),
        jnz_taken: extract_array::<{ components::jnz_opcode_taken::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        jump_rel: extract_array::<{ components::jump_opcode_rel::N_TRACE_COLUMNS }>(slice, offset),
        jump_rel_imm: extract_array::<{ components::jump_opcode_rel_imm::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        mul: extract_array::<{ components::mul_opcode::N_TRACE_COLUMNS }>(slice, offset),
        mul_small: extract_array::<{ components::mul_opcode_small::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        qm31: extract_array::<{ components::qm_31_add_mul_opcode::N_TRACE_COLUMNS }>(slice, offset),
        ret: extract_array::<{ components::ret_opcode::N_TRACE_COLUMNS }>(slice, offset),
    }
}

/// Allocate BlakeTraceSampleResultVar from slice
fn allocate_blake(
    cs: &ConstraintSystemRef,
    slice: &[&QM31Var],
    offset: &mut usize,
) -> BlakeTraceSampleResultVar {
    BlakeTraceSampleResultVar {
        cs: cs.clone(),
        round: extract_array::<{ components::blake_round::N_TRACE_COLUMNS }>(slice, offset),
        g: extract_array::<{ components::blake_g::N_TRACE_COLUMNS }>(slice, offset),
        sigma: extract_array::<{ components::blake_round_sigma::N_TRACE_COLUMNS }>(slice, offset),
        triple_xor_32: extract_array::<{ components::triple_xor_32::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        verify_bitwise_xor_12: extract_array::<
            { components::verify_bitwise_xor_12::N_TRACE_COLUMNS },
        >(slice, offset),
    }
}

/// Allocate RangeChecksTraceSampleResultVar from slice
fn allocate_range_checks(
    cs: &ConstraintSystemRef,
    slice: &[&QM31Var],
    offset: &mut usize,
) -> RangeChecksTraceSampleResultVar {
    RangeChecksTraceSampleResultVar {
        cs: cs.clone(),
        range_check_6: extract_array::<{ components::range_check_6::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_8: extract_array::<{ components::range_check_8::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_11: extract_array::<{ components::range_check_11::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_12: extract_array::<{ components::range_check_12::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_18: extract_array::<{ components::range_check_18::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_18_b: extract_array::<{ components::range_check_18_b::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20: extract_array::<{ components::range_check_20::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_b: extract_array::<{ components::range_check_20_b::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_c: extract_array::<{ components::range_check_20_c::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_d: extract_array::<{ components::range_check_20_d::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_e: extract_array::<{ components::range_check_20_e::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_f: extract_array::<{ components::range_check_20_f::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_g: extract_array::<{ components::range_check_20_g::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_20_h: extract_array::<{ components::range_check_20_h::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_4_3: extract_array::<{ components::range_check_4_3::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_4_4: extract_array::<{ components::range_check_4_4::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_5_4: extract_array::<{ components::range_check_5_4::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9: extract_array::<{ components::range_check_9_9::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_b: extract_array::<{ components::range_check_9_9_b::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_c: extract_array::<{ components::range_check_9_9_c::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_d: extract_array::<{ components::range_check_9_9_d::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_e: extract_array::<{ components::range_check_9_9_e::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_f: extract_array::<{ components::range_check_9_9_f::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_g: extract_array::<{ components::range_check_9_9_g::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_9_9_h: extract_array::<{ components::range_check_9_9_h::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_7_2_5: extract_array::<{ components::range_check_7_2_5::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_3_6_6_3: extract_array::<{ components::range_check_3_6_6_3::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_4_4_4_4: extract_array::<{ components::range_check_4_4_4_4::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        range_check_3_3_3_3_3: extract_array::<
            { components::range_check_3_3_3_3_3::N_TRACE_COLUMNS },
        >(slice, offset),
    }
}

/// Allocate VerifyBitwiseTraceSampleResultVar from slice
fn allocate_verify_bitwise(
    cs: &ConstraintSystemRef,
    slice: &[&QM31Var],
    offset: &mut usize,
) -> VerifyBitwiseTraceSampleResultVar {
    VerifyBitwiseTraceSampleResultVar {
        cs: cs.clone(),
        verify_bitwise_xor_4: extract_array::<{ components::verify_bitwise_xor_4::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        verify_bitwise_xor_7: extract_array::<{ components::verify_bitwise_xor_7::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        verify_bitwise_xor_8: extract_array::<{ components::verify_bitwise_xor_8::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
        verify_bitwise_xor_8_b: extract_array::<
            { components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS },
        >(slice, offset),
        verify_bitwise_xor_9: extract_array::<{ components::verify_bitwise_xor_9::N_TRACE_COLUMNS }>(
            slice, offset,
        ),
    }
}

pub struct OpcodesTraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub add: [QM31Var; components::add_opcode::N_TRACE_COLUMNS],
    pub add_small: [QM31Var; components::add_opcode_small::N_TRACE_COLUMNS],
    pub add_ap: [QM31Var; components::add_ap_opcode::N_TRACE_COLUMNS],
    pub assert_eq: [QM31Var; components::assert_eq_opcode::N_TRACE_COLUMNS],
    pub assert_eq_imm: [QM31Var; components::assert_eq_opcode_imm::N_TRACE_COLUMNS],
    pub assert_eq_double_deref:
        [QM31Var; components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS],
    pub blake: [QM31Var; components::blake_compress_opcode::N_TRACE_COLUMNS],
    pub call: [QM31Var; components::call_opcode_abs::N_TRACE_COLUMNS],
    pub call_rel_imm: [QM31Var; components::call_opcode_rel_imm::N_TRACE_COLUMNS],
    pub jnz: [QM31Var; components::jnz_opcode_non_taken::N_TRACE_COLUMNS],
    pub jnz_taken: [QM31Var; components::jnz_opcode_taken::N_TRACE_COLUMNS],
    pub jump_rel: [QM31Var; components::jump_opcode_rel::N_TRACE_COLUMNS],
    pub jump_rel_imm: [QM31Var; components::jump_opcode_rel_imm::N_TRACE_COLUMNS],
    pub mul: [QM31Var; components::mul_opcode::N_TRACE_COLUMNS],
    pub mul_small: [QM31Var; components::mul_opcode_small::N_TRACE_COLUMNS],
    pub qm31: [QM31Var; components::qm_31_add_mul_opcode::N_TRACE_COLUMNS],
    pub ret: [QM31Var; components::ret_opcode::N_TRACE_COLUMNS],
}

pub struct BlakeTraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub round: [QM31Var; components::blake_round::N_TRACE_COLUMNS],
    pub g: [QM31Var; components::blake_g::N_TRACE_COLUMNS],
    pub sigma: [QM31Var; components::blake_round_sigma::N_TRACE_COLUMNS],
    pub triple_xor_32: [QM31Var; components::triple_xor_32::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_12: [QM31Var; components::verify_bitwise_xor_12::N_TRACE_COLUMNS],
}

pub struct RangeChecksTraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: [QM31Var; components::range_check_6::N_TRACE_COLUMNS],
    pub range_check_8: [QM31Var; components::range_check_8::N_TRACE_COLUMNS],
    pub range_check_11: [QM31Var; components::range_check_11::N_TRACE_COLUMNS],
    pub range_check_12: [QM31Var; components::range_check_12::N_TRACE_COLUMNS],
    pub range_check_18: [QM31Var; components::range_check_18::N_TRACE_COLUMNS],
    pub range_check_18_b: [QM31Var; components::range_check_18_b::N_TRACE_COLUMNS],
    pub range_check_20: [QM31Var; components::range_check_20::N_TRACE_COLUMNS],
    pub range_check_20_b: [QM31Var; components::range_check_20_b::N_TRACE_COLUMNS],
    pub range_check_20_c: [QM31Var; components::range_check_20_c::N_TRACE_COLUMNS],
    pub range_check_20_d: [QM31Var; components::range_check_20_d::N_TRACE_COLUMNS],
    pub range_check_20_e: [QM31Var; components::range_check_20_e::N_TRACE_COLUMNS],
    pub range_check_20_f: [QM31Var; components::range_check_20_f::N_TRACE_COLUMNS],
    pub range_check_20_g: [QM31Var; components::range_check_20_g::N_TRACE_COLUMNS],
    pub range_check_20_h: [QM31Var; components::range_check_20_h::N_TRACE_COLUMNS],
    pub range_check_4_3: [QM31Var; components::range_check_4_3::N_TRACE_COLUMNS],
    pub range_check_4_4: [QM31Var; components::range_check_4_4::N_TRACE_COLUMNS],
    pub range_check_5_4: [QM31Var; components::range_check_5_4::N_TRACE_COLUMNS],
    pub range_check_9_9: [QM31Var; components::range_check_9_9::N_TRACE_COLUMNS],
    pub range_check_9_9_b: [QM31Var; components::range_check_9_9_b::N_TRACE_COLUMNS],
    pub range_check_9_9_c: [QM31Var; components::range_check_9_9_c::N_TRACE_COLUMNS],
    pub range_check_9_9_d: [QM31Var; components::range_check_9_9_d::N_TRACE_COLUMNS],
    pub range_check_9_9_e: [QM31Var; components::range_check_9_9_e::N_TRACE_COLUMNS],
    pub range_check_9_9_f: [QM31Var; components::range_check_9_9_f::N_TRACE_COLUMNS],
    pub range_check_9_9_g: [QM31Var; components::range_check_9_9_g::N_TRACE_COLUMNS],
    pub range_check_9_9_h: [QM31Var; components::range_check_9_9_h::N_TRACE_COLUMNS],
    pub range_check_7_2_5: [QM31Var; components::range_check_7_2_5::N_TRACE_COLUMNS],
    pub range_check_3_6_6_3: [QM31Var; components::range_check_3_6_6_3::N_TRACE_COLUMNS],
    pub range_check_4_4_4_4: [QM31Var; components::range_check_4_4_4_4::N_TRACE_COLUMNS],
    pub range_check_3_3_3_3_3: [QM31Var; components::range_check_3_3_3_3_3::N_TRACE_COLUMNS],
}

pub struct VerifyBitwiseTraceSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: [QM31Var; components::verify_bitwise_xor_4::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_7: [QM31Var; components::verify_bitwise_xor_7::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8: [QM31Var; components::verify_bitwise_xor_8::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8_b: [QM31Var; components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_9: [QM31Var; components::verify_bitwise_xor_9::N_TRACE_COLUMNS],
}
