use cairo_air::components;
use cairo_plonk_dsl_data_structures::CairoClaimVar;
use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use circle_plonk_dsl_constraint_system::{var::Var, ConstraintSystemRef};
use circle_plonk_dsl_primitives::{
    CM31Var, CirclePointM31Var, CirclePointQM31Var, LogSizeVar, M31Var, QM31Var,
};
use indexmap::IndexMap;
use itertools::Itertools;
use stwo_cairo_common::{
    preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE,
    prover_types::simd::LOG_N_LANES,
};

use crate::AnswerAccumulator;

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

// QuotientConstantsVar structs - replacing QM31Var with [CM31Var; 2]

pub struct TraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesTraceQuotientConstantsVar,
    pub verify_instruction: [[CM31Var; 2]; components::verify_instruction::N_TRACE_COLUMNS],
    pub blake: BlakeTraceQuotientConstantsVar,
    pub range_check_128_builtin:
        [[CM31Var; 2]; components::range_check_builtin_bits_128::N_TRACE_COLUMNS],
    pub memory_address_to_id: [[CM31Var; 2]; components::memory_address_to_id::N_TRACE_COLUMNS],
    pub memory_id_to_big_big: [[CM31Var; 2]; components::memory_id_to_big::BIG_N_COLUMNS],
    pub memory_id_to_big_small: [[CM31Var; 2]; components::memory_id_to_big::SMALL_N_COLUMNS],
    pub range_checks: RangeChecksTraceQuotientConstantsVar,
    pub verify_bitwise: VerifyBitwiseTraceQuotientConstantsVar,
}

impl TraceQuotientConstantsVar {
    pub fn new(oods_point: &CirclePointQM31Var, sample_result: &TraceSampleResultVar) -> Self {
        use super::complex_conjugate_line_coeffs_var;
        Self {
            cs: sample_result.cs.clone(),
            opcodes: OpcodesTraceQuotientConstantsVar::new(oods_point, &sample_result.opcodes),
            verify_instruction: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(oods_point, &sample_result.verify_instruction[i])
            }),
            blake: BlakeTraceQuotientConstantsVar::new(oods_point, &sample_result.blake),
            range_check_128_builtin: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.range_check_128_builtin[i],
                )
            }),
            memory_address_to_id: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.memory_address_to_id[i],
                )
            }),
            memory_id_to_big_big: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.memory_id_to_big_big[i],
                )
            }),
            memory_id_to_big_small: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.memory_id_to_big_small[i],
                )
            }),
            range_checks: RangeChecksTraceQuotientConstantsVar::new(
                oods_point,
                &sample_result.range_checks,
            ),
            verify_bitwise: VerifyBitwiseTraceQuotientConstantsVar::new(
                oods_point,
                &sample_result.verify_bitwise,
            ),
        }
    }
}

pub struct OpcodesTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub add: [[CM31Var; 2]; components::add_opcode::N_TRACE_COLUMNS],
    pub add_small: [[CM31Var; 2]; components::add_opcode_small::N_TRACE_COLUMNS],
    pub add_ap: [[CM31Var; 2]; components::add_ap_opcode::N_TRACE_COLUMNS],
    pub assert_eq: [[CM31Var; 2]; components::assert_eq_opcode::N_TRACE_COLUMNS],
    pub assert_eq_imm: [[CM31Var; 2]; components::assert_eq_opcode_imm::N_TRACE_COLUMNS],
    pub assert_eq_double_deref:
        [[CM31Var; 2]; components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS],
    pub blake: [[CM31Var; 2]; components::blake_compress_opcode::N_TRACE_COLUMNS],
    pub call: [[CM31Var; 2]; components::call_opcode_abs::N_TRACE_COLUMNS],
    pub call_rel_imm: [[CM31Var; 2]; components::call_opcode_rel_imm::N_TRACE_COLUMNS],
    pub jnz: [[CM31Var; 2]; components::jnz_opcode_non_taken::N_TRACE_COLUMNS],
    pub jnz_taken: [[CM31Var; 2]; components::jnz_opcode_taken::N_TRACE_COLUMNS],
    pub jump_rel: [[CM31Var; 2]; components::jump_opcode_rel::N_TRACE_COLUMNS],
    pub jump_rel_imm: [[CM31Var; 2]; components::jump_opcode_rel_imm::N_TRACE_COLUMNS],
    pub mul: [[CM31Var; 2]; components::mul_opcode::N_TRACE_COLUMNS],
    pub mul_small: [[CM31Var; 2]; components::mul_opcode_small::N_TRACE_COLUMNS],
    pub qm31: [[CM31Var; 2]; components::qm_31_add_mul_opcode::N_TRACE_COLUMNS],
    pub ret: [[CM31Var; 2]; components::ret_opcode::N_TRACE_COLUMNS],
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
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.assert_eq_double_deref[i],
                )
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
    pub round: [[CM31Var; 2]; components::blake_round::N_TRACE_COLUMNS],
    pub g: [[CM31Var; 2]; components::blake_g::N_TRACE_COLUMNS],
    pub sigma: [[CM31Var; 2]; components::blake_round_sigma::N_TRACE_COLUMNS],
    pub triple_xor_32: [[CM31Var; 2]; components::triple_xor_32::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_12: [[CM31Var; 2]; components::verify_bitwise_xor_12::N_TRACE_COLUMNS],
}

impl BlakeTraceQuotientConstantsVar {
    pub fn new(oods_point: &CirclePointQM31Var, sample_result: &BlakeTraceSampleResultVar) -> Self {
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
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.verify_bitwise_xor_12[i],
                )
            }),
        }
    }
}

pub struct RangeChecksTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: [[CM31Var; 2]; components::range_check_6::N_TRACE_COLUMNS],
    pub range_check_8: [[CM31Var; 2]; components::range_check_8::N_TRACE_COLUMNS],
    pub range_check_11: [[CM31Var; 2]; components::range_check_11::N_TRACE_COLUMNS],
    pub range_check_12: [[CM31Var; 2]; components::range_check_12::N_TRACE_COLUMNS],
    pub range_check_18: [[CM31Var; 2]; components::range_check_18::N_TRACE_COLUMNS],
    pub range_check_18_b: [[CM31Var; 2]; components::range_check_18_b::N_TRACE_COLUMNS],
    pub range_check_20: [[CM31Var; 2]; components::range_check_20::N_TRACE_COLUMNS],
    pub range_check_20_b: [[CM31Var; 2]; components::range_check_20_b::N_TRACE_COLUMNS],
    pub range_check_20_c: [[CM31Var; 2]; components::range_check_20_c::N_TRACE_COLUMNS],
    pub range_check_20_d: [[CM31Var; 2]; components::range_check_20_d::N_TRACE_COLUMNS],
    pub range_check_20_e: [[CM31Var; 2]; components::range_check_20_e::N_TRACE_COLUMNS],
    pub range_check_20_f: [[CM31Var; 2]; components::range_check_20_f::N_TRACE_COLUMNS],
    pub range_check_20_g: [[CM31Var; 2]; components::range_check_20_g::N_TRACE_COLUMNS],
    pub range_check_20_h: [[CM31Var; 2]; components::range_check_20_h::N_TRACE_COLUMNS],
    pub range_check_4_3: [[CM31Var; 2]; components::range_check_4_3::N_TRACE_COLUMNS],
    pub range_check_4_4: [[CM31Var; 2]; components::range_check_4_4::N_TRACE_COLUMNS],
    pub range_check_5_4: [[CM31Var; 2]; components::range_check_5_4::N_TRACE_COLUMNS],
    pub range_check_9_9: [[CM31Var; 2]; components::range_check_9_9::N_TRACE_COLUMNS],
    pub range_check_9_9_b: [[CM31Var; 2]; components::range_check_9_9_b::N_TRACE_COLUMNS],
    pub range_check_9_9_c: [[CM31Var; 2]; components::range_check_9_9_c::N_TRACE_COLUMNS],
    pub range_check_9_9_d: [[CM31Var; 2]; components::range_check_9_9_d::N_TRACE_COLUMNS],
    pub range_check_9_9_e: [[CM31Var; 2]; components::range_check_9_9_e::N_TRACE_COLUMNS],
    pub range_check_9_9_f: [[CM31Var; 2]; components::range_check_9_9_f::N_TRACE_COLUMNS],
    pub range_check_9_9_g: [[CM31Var; 2]; components::range_check_9_9_g::N_TRACE_COLUMNS],
    pub range_check_9_9_h: [[CM31Var; 2]; components::range_check_9_9_h::N_TRACE_COLUMNS],
    pub range_check_7_2_5: [[CM31Var; 2]; components::range_check_7_2_5::N_TRACE_COLUMNS],
    pub range_check_3_6_6_3: [[CM31Var; 2]; components::range_check_3_6_6_3::N_TRACE_COLUMNS],
    pub range_check_4_4_4_4: [[CM31Var; 2]; components::range_check_4_4_4_4::N_TRACE_COLUMNS],
    pub range_check_3_3_3_3_3: [[CM31Var; 2]; components::range_check_3_3_3_3_3::N_TRACE_COLUMNS],
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
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.range_check_3_3_3_3_3[i],
                )
            }),
        }
    }
}

pub struct VerifyBitwiseTraceQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: [[CM31Var; 2]; components::verify_bitwise_xor_4::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_7: [[CM31Var; 2]; components::verify_bitwise_xor_7::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8: [[CM31Var; 2]; components::verify_bitwise_xor_8::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8_b: [[CM31Var; 2]; components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_9: [[CM31Var; 2]; components::verify_bitwise_xor_9::N_TRACE_COLUMNS],
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
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.verify_bitwise_xor_4[i],
                )
            }),
            verify_bitwise_xor_7: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.verify_bitwise_xor_7[i],
                )
            }),
            verify_bitwise_xor_8: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.verify_bitwise_xor_8[i],
                )
            }),
            verify_bitwise_xor_8_b: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.verify_bitwise_xor_8_b[i],
                )
            }),
            verify_bitwise_xor_9: std::array::from_fn(|i| {
                complex_conjugate_line_coeffs_var(
                    oods_point,
                    &sample_result.verify_bitwise_xor_9[i],
                )
            }),
        }
    }
}

pub fn compute_trace_answers(
    num_queries: usize,
    answer_accumulator: &mut Vec<AnswerAccumulator>,
    oods_point_y: &CM31Var,
    domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
    denominator_inverses_with_oods_point: &IndexMap<u32, Vec<CM31Var>>,
    query_result: &CairoDecommitmentResultsVar,
    quotient_constants: &TraceQuotientConstantsVar,
    claim: &CairoClaimVar,
) {
    let update = |answer_accumulator: &mut AnswerAccumulator,
                  log_size: &LogSizeVar,
                  query: &[M31Var],
                  quotient_constants: &[[CM31Var; 2]],
                  idx: usize| {
        let cs = oods_point_y.cs();
        let mut x = M31Var::zero(&cs);
        let mut y = M31Var::zero(&cs);
        let mut denominator_inverse = CM31Var::zero(&cs);

        for i in (LOG_N_LANES + 1)..=(MAX_SEQUENCE_LOG_SIZE + 1) {
            let bit = log_size.bitmap.get(&(i - 1)).unwrap();
            x = &x + &(&bit.0 * &domain_points.get(&i).unwrap()[idx].x);
            y = &y + &(&bit.0 * &domain_points.get(&i).unwrap()[idx].y);
            denominator_inverse = &denominator_inverse
                + &(&denominator_inverses_with_oods_point.get(&i).unwrap()[idx] * &bit.0);
        }

        let update = quotient_constants
            .iter()
            .zip_eq(query.iter())
            .map(|(quotient_constants, query)| {
                &denominator_inverse
                    * &(&(&(oods_point_y * query) - &(&quotient_constants[0] * &y))
                        - &quotient_constants[1])
            })
            .collect_vec();
        answer_accumulator.update(log_size, &update);
    };

    let update_fixed_log_size = |answer_accumulator: &mut AnswerAccumulator,
                                 log_size: u32,
                                 query: &[M31Var],
                                 quotient_constants: &[[CM31Var; 2]],
                                 idx: usize| {
        let query_point = &domain_points.get(&(log_size + 1)).unwrap()[idx];
        let denominator_inverse = &denominator_inverses_with_oods_point
            .get(&(log_size + 1))
            .unwrap()[idx];
        let update = quotient_constants
            .iter()
            .zip_eq(query.iter())
            .map(|(quotient_constants, query)| {
                denominator_inverse
                    * &(&(&(oods_point_y * query) - &(&quotient_constants[0] * &query_point.y))
                        - &quotient_constants[1])
            })
            .collect_vec();
        answer_accumulator.update_fix_log_size(log_size as usize, &update);
    };

    for idx in 0..num_queries {
        let answer_accumulator = &mut answer_accumulator[idx];
        let query_result = &query_result[idx].trace_query_result;

        // opcodes
        update(
            answer_accumulator,
            &claim.opcode_claim.add,
            &query_result.opcodes.add,
            &quotient_constants.opcodes.add,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.add_small,
            &query_result.opcodes.add_small,
            &quotient_constants.opcodes.add_small,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.add_ap,
            &query_result.opcodes.add_ap,
            &quotient_constants.opcodes.add_ap,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.assert_eq,
            &query_result.opcodes.assert_eq,
            &quotient_constants.opcodes.assert_eq,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.assert_eq_imm,
            &query_result.opcodes.assert_eq_imm,
            &quotient_constants.opcodes.assert_eq_imm,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.assert_eq_double_deref,
            &query_result.opcodes.assert_eq_double_deref,
            &quotient_constants.opcodes.assert_eq_double_deref,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.blake,
            &query_result.opcodes.blake,
            &quotient_constants.opcodes.blake,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.call,
            &query_result.opcodes.call,
            &quotient_constants.opcodes.call,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.call_rel_imm,
            &query_result.opcodes.call_rel_imm,
            &quotient_constants.opcodes.call_rel_imm,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.jnz,
            &query_result.opcodes.jnz,
            &quotient_constants.opcodes.jnz,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.jnz_taken,
            &query_result.opcodes.jnz_taken,
            &quotient_constants.opcodes.jnz_taken,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.jump_rel,
            &query_result.opcodes.jump_rel,
            &quotient_constants.opcodes.jump_rel,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.jump_rel_imm,
            &query_result.opcodes.jump_rel_imm,
            &quotient_constants.opcodes.jump_rel_imm,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.mul,
            &query_result.opcodes.mul,
            &quotient_constants.opcodes.mul,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.mul_small,
            &query_result.opcodes.mul_small,
            &quotient_constants.opcodes.mul_small,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.qm31,
            &query_result.opcodes.qm31,
            &quotient_constants.opcodes.qm31,
            idx,
        );
        update(
            answer_accumulator,
            &claim.opcode_claim.ret,
            &query_result.opcodes.ret,
            &quotient_constants.opcodes.ret,
            idx,
        );

        // verify_instruction
        update(
            answer_accumulator,
            &claim.verify_instruction,
            &query_result.verify_instruction,
            &quotient_constants.verify_instruction,
            idx,
        );

        // blake
        update(
            answer_accumulator,
            &claim.blake_context.blake_round,
            &query_result.blake.round,
            &quotient_constants.blake.round,
            idx,
        );
        update(
            answer_accumulator,
            &claim.blake_context.blake_g,
            &query_result.blake.g,
            &quotient_constants.blake.g,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::blake_round_sigma::LOG_SIZE,
            &query_result.blake.sigma,
            &quotient_constants.blake.sigma,
            idx,
        );
        update(
            answer_accumulator,
            &claim.blake_context.triple_xor_32,
            &query_result.blake.triple_xor_32,
            &quotient_constants.blake.triple_xor_32,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
            &query_result.blake.verify_bitwise_xor_12,
            &quotient_constants.blake.verify_bitwise_xor_12,
            idx,
        );

        // range_check_128_builtin
        update(
            answer_accumulator,
            &claim.builtins.range_check_128_builtin_log_size,
            &query_result.range_check_128_builtin,
            &quotient_constants.range_check_128_builtin,
            idx,
        );

        // memory_address_to_id
        update(
            answer_accumulator,
            &claim.memory_address_to_id,
            &query_result.memory_address_to_id,
            &quotient_constants.memory_address_to_id,
            idx,
        );

        // memory_id_to_big_big
        update(
            answer_accumulator,
            &claim.memory_id_to_value.big_log_size,
            &query_result.memory_id_to_big_big,
            &quotient_constants.memory_id_to_big_big,
            idx,
        );

        // memory_id_to_big_small
        update(
            answer_accumulator,
            &claim.memory_id_to_value.small_log_size,
            &query_result.memory_id_to_big_small,
            &quotient_constants.memory_id_to_big_small,
            idx,
        );

        // range_checks
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_6::LOG_SIZE,
            &query_result.range_checks.range_check_6,
            &quotient_constants.range_checks.range_check_6,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_8::LOG_SIZE,
            &query_result.range_checks.range_check_8,
            &quotient_constants.range_checks.range_check_8,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_11::LOG_SIZE,
            &query_result.range_checks.range_check_11,
            &quotient_constants.range_checks.range_check_11,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_12::LOG_SIZE,
            &query_result.range_checks.range_check_12,
            &quotient_constants.range_checks.range_check_12,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_18::LOG_SIZE,
            &query_result.range_checks.range_check_18,
            &quotient_constants.range_checks.range_check_18,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_18_b::LOG_SIZE,
            &query_result.range_checks.range_check_18_b,
            &quotient_constants.range_checks.range_check_18_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20::LOG_SIZE,
            &query_result.range_checks.range_check_20,
            &quotient_constants.range_checks.range_check_20,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_b::LOG_SIZE,
            &query_result.range_checks.range_check_20_b,
            &quotient_constants.range_checks.range_check_20_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_c::LOG_SIZE,
            &query_result.range_checks.range_check_20_c,
            &quotient_constants.range_checks.range_check_20_c,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_d::LOG_SIZE,
            &query_result.range_checks.range_check_20_d,
            &quotient_constants.range_checks.range_check_20_d,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_e::LOG_SIZE,
            &query_result.range_checks.range_check_20_e,
            &quotient_constants.range_checks.range_check_20_e,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_f::LOG_SIZE,
            &query_result.range_checks.range_check_20_f,
            &quotient_constants.range_checks.range_check_20_f,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_g::LOG_SIZE,
            &query_result.range_checks.range_check_20_g,
            &quotient_constants.range_checks.range_check_20_g,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_20_h::LOG_SIZE,
            &query_result.range_checks.range_check_20_h,
            &quotient_constants.range_checks.range_check_20_h,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_4_3::LOG_SIZE,
            &query_result.range_checks.range_check_4_3,
            &quotient_constants.range_checks.range_check_4_3,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_4_4::LOG_SIZE,
            &query_result.range_checks.range_check_4_4,
            &quotient_constants.range_checks.range_check_4_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_5_4::LOG_SIZE,
            &query_result.range_checks.range_check_5_4,
            &quotient_constants.range_checks.range_check_5_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9::LOG_SIZE,
            &query_result.range_checks.range_check_9_9,
            &quotient_constants.range_checks.range_check_9_9,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_b::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_b,
            &quotient_constants.range_checks.range_check_9_9_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_c::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_c,
            &quotient_constants.range_checks.range_check_9_9_c,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_d::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_d,
            &quotient_constants.range_checks.range_check_9_9_d,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_e::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_e,
            &quotient_constants.range_checks.range_check_9_9_e,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_f::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_f,
            &quotient_constants.range_checks.range_check_9_9_f,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_g::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_g,
            &quotient_constants.range_checks.range_check_9_9_g,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_9_9_h::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_h,
            &quotient_constants.range_checks.range_check_9_9_h,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_7_2_5::LOG_SIZE,
            &query_result.range_checks.range_check_7_2_5,
            &quotient_constants.range_checks.range_check_7_2_5,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_3_6_6_3::LOG_SIZE,
            &query_result.range_checks.range_check_3_6_6_3,
            &quotient_constants.range_checks.range_check_3_6_6_3,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_4_4_4_4::LOG_SIZE,
            &query_result.range_checks.range_check_4_4_4_4,
            &quotient_constants.range_checks.range_check_4_4_4_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::range_check_3_3_3_3_3::LOG_SIZE,
            &query_result.range_checks.range_check_3_3_3_3_3,
            &quotient_constants.range_checks.range_check_3_3_3_3_3,
            idx,
        );

        // verify_bitwise
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::verify_bitwise_xor_4::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_4,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::verify_bitwise_xor_7::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_7,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_7,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::verify_bitwise_xor_8::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_8,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_8,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::verify_bitwise_xor_8_b::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_8_b,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_8_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            cairo_air::components::verify_bitwise_xor_9::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_9,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_9,
            idx,
        );
    }
}
