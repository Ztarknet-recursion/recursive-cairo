use cairo_air::components;
use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_primitives::{CM31Var, CirclePointQM31Var, QM31Var};

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

// QuotientConstantsVar structs - replacing QM31Var with [CM31Var; 3]

pub struct TraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesTraceQuotientConstantsVar,
    pub verify_instruction: [[CM31Var; 3]; components::verify_instruction::N_TRACE_COLUMNS],
    pub blake: BlakeTraceQuotientConstantsVar,
    pub range_check_128_builtin:
        [[CM31Var; 3]; components::range_check_builtin_bits_128::N_TRACE_COLUMNS],
    pub memory_address_to_id: [[CM31Var; 3]; components::memory_address_to_id::N_TRACE_COLUMNS],
    pub memory_id_to_big_big: [[CM31Var; 3]; components::memory_id_to_big::BIG_N_COLUMNS],
    pub memory_id_to_big_small: [[CM31Var; 3]; components::memory_id_to_big::SMALL_N_COLUMNS],
    pub range_checks: RangeChecksTraceQuotientConstantsVar,
    pub verify_bitwise: VerifyBitwiseTraceQuotientConstantsVar,
}

impl TraceQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        sample_result: &TraceSampleResultVar,
    ) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            opcodes: OpcodesTraceQuotientConstantsVar::new(oods_point, &sample_result.opcodes),
            verify_instruction: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_instruction[i])
            }),
            blake: BlakeTraceQuotientConstantsVar::new(oods_point, &sample_result.blake),
            range_check_128_builtin: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_128_builtin[i])
            }),
            memory_address_to_id: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.memory_address_to_id[i])
            }),
            memory_id_to_big_big: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.memory_id_to_big_big[i])
            }),
            memory_id_to_big_small: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.memory_id_to_big_small[i])
            }),
            range_checks: RangeChecksTraceQuotientConstantsVar::new(oods_point, &sample_result.range_checks),
            verify_bitwise: VerifyBitwiseTraceQuotientConstantsVar::new(oods_point, &sample_result.verify_bitwise),
        }
    }
}

pub struct OpcodesTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub add: [[CM31Var; 3]; components::add_opcode::N_TRACE_COLUMNS],
    pub add_small: [[CM31Var; 3]; components::add_opcode_small::N_TRACE_COLUMNS],
    pub add_ap: [[CM31Var; 3]; components::add_ap_opcode::N_TRACE_COLUMNS],
    pub assert_eq: [[CM31Var; 3]; components::assert_eq_opcode::N_TRACE_COLUMNS],
    pub assert_eq_imm: [[CM31Var; 3]; components::assert_eq_opcode_imm::N_TRACE_COLUMNS],
    pub assert_eq_double_deref:
        [[CM31Var; 3]; components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS],
    pub blake: [[CM31Var; 3]; components::blake_compress_opcode::N_TRACE_COLUMNS],
    pub call: [[CM31Var; 3]; components::call_opcode_abs::N_TRACE_COLUMNS],
    pub call_rel_imm: [[CM31Var; 3]; components::call_opcode_rel_imm::N_TRACE_COLUMNS],
    pub jnz: [[CM31Var; 3]; components::jnz_opcode_non_taken::N_TRACE_COLUMNS],
    pub jnz_taken: [[CM31Var; 3]; components::jnz_opcode_taken::N_TRACE_COLUMNS],
    pub jump_rel: [[CM31Var; 3]; components::jump_opcode_rel::N_TRACE_COLUMNS],
    pub jump_rel_imm: [[CM31Var; 3]; components::jump_opcode_rel_imm::N_TRACE_COLUMNS],
    pub mul: [[CM31Var; 3]; components::mul_opcode::N_TRACE_COLUMNS],
    pub mul_small: [[CM31Var; 3]; components::mul_opcode_small::N_TRACE_COLUMNS],
    pub qm31: [[CM31Var; 3]; components::qm_31_add_mul_opcode::N_TRACE_COLUMNS],
    pub ret: [[CM31Var; 3]; components::ret_opcode::N_TRACE_COLUMNS],
}

impl OpcodesTraceQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        sample_result: &OpcodesTraceSampleResultVar,
    ) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            add: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.add[i])
            }),
            add_small: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.add_small[i])
            }),
            add_ap: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.add_ap[i])
            }),
            assert_eq: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.assert_eq[i])
            }),
            assert_eq_imm: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.assert_eq_imm[i])
            }),
            assert_eq_double_deref: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.assert_eq_double_deref[i])
            }),
            blake: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.blake[i])
            }),
            call: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.call[i])
            }),
            call_rel_imm: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.call_rel_imm[i])
            }),
            jnz: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.jnz[i])
            }),
            jnz_taken: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.jnz_taken[i])
            }),
            jump_rel: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.jump_rel[i])
            }),
            jump_rel_imm: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.jump_rel_imm[i])
            }),
            mul: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.mul[i])
            }),
            mul_small: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.mul_small[i])
            }),
            qm31: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.qm31[i])
            }),
            ret: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.ret[i])
            }),
        }
    }
}

pub struct BlakeTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub round: [[CM31Var; 3]; components::blake_round::N_TRACE_COLUMNS],
    pub g: [[CM31Var; 3]; components::blake_g::N_TRACE_COLUMNS],
    pub sigma: [[CM31Var; 3]; components::blake_round_sigma::N_TRACE_COLUMNS],
    pub triple_xor_32: [[CM31Var; 3]; components::triple_xor_32::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_12: [[CM31Var; 3]; components::verify_bitwise_xor_12::N_TRACE_COLUMNS],
}

impl BlakeTraceQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        sample_result: &BlakeTraceSampleResultVar,
    ) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            round: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.round[i])
            }),
            g: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.g[i])
            }),
            sigma: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.sigma[i])
            }),
            triple_xor_32: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.triple_xor_32[i])
            }),
            verify_bitwise_xor_12: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_bitwise_xor_12[i])
            }),
        }
    }
}

pub struct RangeChecksTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: [[CM31Var; 3]; components::range_check_6::N_TRACE_COLUMNS],
    pub range_check_8: [[CM31Var; 3]; components::range_check_8::N_TRACE_COLUMNS],
    pub range_check_11: [[CM31Var; 3]; components::range_check_11::N_TRACE_COLUMNS],
    pub range_check_12: [[CM31Var; 3]; components::range_check_12::N_TRACE_COLUMNS],
    pub range_check_18: [[CM31Var; 3]; components::range_check_18::N_TRACE_COLUMNS],
    pub range_check_18_b: [[CM31Var; 3]; components::range_check_18_b::N_TRACE_COLUMNS],
    pub range_check_20: [[CM31Var; 3]; components::range_check_20::N_TRACE_COLUMNS],
    pub range_check_20_b: [[CM31Var; 3]; components::range_check_20_b::N_TRACE_COLUMNS],
    pub range_check_20_c: [[CM31Var; 3]; components::range_check_20_c::N_TRACE_COLUMNS],
    pub range_check_20_d: [[CM31Var; 3]; components::range_check_20_d::N_TRACE_COLUMNS],
    pub range_check_20_e: [[CM31Var; 3]; components::range_check_20_e::N_TRACE_COLUMNS],
    pub range_check_20_f: [[CM31Var; 3]; components::range_check_20_f::N_TRACE_COLUMNS],
    pub range_check_20_g: [[CM31Var; 3]; components::range_check_20_g::N_TRACE_COLUMNS],
    pub range_check_20_h: [[CM31Var; 3]; components::range_check_20_h::N_TRACE_COLUMNS],
    pub range_check_4_3: [[CM31Var; 3]; components::range_check_4_3::N_TRACE_COLUMNS],
    pub range_check_4_4: [[CM31Var; 3]; components::range_check_4_4::N_TRACE_COLUMNS],
    pub range_check_5_4: [[CM31Var; 3]; components::range_check_5_4::N_TRACE_COLUMNS],
    pub range_check_9_9: [[CM31Var; 3]; components::range_check_9_9::N_TRACE_COLUMNS],
    pub range_check_9_9_b: [[CM31Var; 3]; components::range_check_9_9_b::N_TRACE_COLUMNS],
    pub range_check_9_9_c: [[CM31Var; 3]; components::range_check_9_9_c::N_TRACE_COLUMNS],
    pub range_check_9_9_d: [[CM31Var; 3]; components::range_check_9_9_d::N_TRACE_COLUMNS],
    pub range_check_9_9_e: [[CM31Var; 3]; components::range_check_9_9_e::N_TRACE_COLUMNS],
    pub range_check_9_9_f: [[CM31Var; 3]; components::range_check_9_9_f::N_TRACE_COLUMNS],
    pub range_check_9_9_g: [[CM31Var; 3]; components::range_check_9_9_g::N_TRACE_COLUMNS],
    pub range_check_9_9_h: [[CM31Var; 3]; components::range_check_9_9_h::N_TRACE_COLUMNS],
    pub range_check_7_2_5: [[CM31Var; 3]; components::range_check_7_2_5::N_TRACE_COLUMNS],
    pub range_check_3_6_6_3: [[CM31Var; 3]; components::range_check_3_6_6_3::N_TRACE_COLUMNS],
    pub range_check_4_4_4_4: [[CM31Var; 3]; components::range_check_4_4_4_4::N_TRACE_COLUMNS],
    pub range_check_3_3_3_3_3: [[CM31Var; 3]; components::range_check_3_3_3_3_3::N_TRACE_COLUMNS],
}

impl RangeChecksTraceQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        sample_result: &RangeChecksTraceSampleResultVar,
    ) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            range_check_6: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_6[i])
            }),
            range_check_8: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_8[i])
            }),
            range_check_11: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_11[i])
            }),
            range_check_12: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_12[i])
            }),
            range_check_18: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_18[i])
            }),
            range_check_18_b: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_18_b[i])
            }),
            range_check_20: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20[i])
            }),
            range_check_20_b: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_b[i])
            }),
            range_check_20_c: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_c[i])
            }),
            range_check_20_d: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_d[i])
            }),
            range_check_20_e: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_e[i])
            }),
            range_check_20_f: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_f[i])
            }),
            range_check_20_g: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_g[i])
            }),
            range_check_20_h: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_20_h[i])
            }),
            range_check_4_3: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_4_3[i])
            }),
            range_check_4_4: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_4_4[i])
            }),
            range_check_5_4: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_5_4[i])
            }),
            range_check_9_9: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9[i])
            }),
            range_check_9_9_b: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_b[i])
            }),
            range_check_9_9_c: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_c[i])
            }),
            range_check_9_9_d: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_d[i])
            }),
            range_check_9_9_e: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_e[i])
            }),
            range_check_9_9_f: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_f[i])
            }),
            range_check_9_9_g: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_g[i])
            }),
            range_check_9_9_h: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_9_9_h[i])
            }),
            range_check_7_2_5: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_7_2_5[i])
            }),
            range_check_3_6_6_3: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_3_6_6_3[i])
            }),
            range_check_4_4_4_4: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_4_4_4_4[i])
            }),
            range_check_3_3_3_3_3: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.range_check_3_3_3_3_3[i])
            }),
        }
    }
}

pub struct VerifyBitwiseTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: [[CM31Var; 3]; components::verify_bitwise_xor_4::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_7: [[CM31Var; 3]; components::verify_bitwise_xor_7::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8: [[CM31Var; 3]; components::verify_bitwise_xor_8::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8_b: [[CM31Var; 3]; components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_9: [[CM31Var; 3]; components::verify_bitwise_xor_9::N_TRACE_COLUMNS],
}

impl VerifyBitwiseTraceQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        sample_result: &VerifyBitwiseTraceSampleResultVar,
    ) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            verify_bitwise_xor_4: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_bitwise_xor_4[i])
            }),
            verify_bitwise_xor_7: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_bitwise_xor_7[i])
            }),
            verify_bitwise_xor_8: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_bitwise_xor_8[i])
            }),
            verify_bitwise_xor_8_b: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_bitwise_xor_8_b[i])
            }),
            verify_bitwise_xor_9: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_bitwise_xor_9[i])
            }),
        }
    }
}

