use cairo_plonk_dsl_data_structures::{BlakeContextClaimVar, CairoClaimVar, OpcodeClaimVar};
use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use circle_plonk_dsl_constraint_system::{var::Var, ConstraintSystemRef};
use circle_plonk_dsl_primitives::{
    oblivious_map::ObliviousMapVar, CM31Var, CirclePointM31Var, CirclePointQM31Var, LogSizeVar,
    M31Var, QM31Var,
};
use indexmap::IndexMap;
use itertools::Itertools;
use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
use stwo_cairo_common::{
    preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE,
    prover_types::simd::LOG_N_LANES,
};

use crate::{complex_conjugate_line_coeffs_var, AnswerAccumulator};

pub struct InteractionEntryVar<const N: usize> {
    pub data: [[QM31Var; SECURE_EXTENSION_DEGREE]; N],
    pub presum: [QM31Var; SECURE_EXTENSION_DEGREE],
}

pub struct InteractionSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesInteractionSampleResultVar,
    pub verify_instruction: InteractionEntryVar<3>,
    pub blake: BlakeInteractionSampleResultVar,
    pub range_check_128_builtin: InteractionEntryVar<1>,
    pub memory_address_to_id: InteractionEntryVar<8>,
    pub memory_id_to_big_big: InteractionEntryVar<8>,
    pub memory_id_to_big_small: InteractionEntryVar<3>,
    pub range_checks: RangeChecksInteractionSampleResultVar,
    pub verify_bitwise: VerifyBitwiseInteractionSampleResultVar,
}

pub struct OpcodesInteractionSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub add: InteractionEntryVar<5>,
    pub add_small: InteractionEntryVar<5>,
    pub add_ap: InteractionEntryVar<4>,
    pub assert_eq: InteractionEntryVar<3>,
    pub assert_eq_imm: InteractionEntryVar<3>,
    pub assert_eq_double_deref: InteractionEntryVar<4>,
    pub blake: InteractionEntryVar<37>,
    pub call: InteractionEntryVar<5>,
    pub call_rel_imm: InteractionEntryVar<5>,
    pub jnz: InteractionEntryVar<3>,
    pub jnz_taken: InteractionEntryVar<4>,
    pub jump_rel: InteractionEntryVar<3>,
    pub jump_rel_imm: InteractionEntryVar<3>,
    pub mul: InteractionEntryVar<19>,
    pub mul_small: InteractionEntryVar<6>,
    pub qm31: InteractionEntryVar<6>,
    pub ret: InteractionEntryVar<4>,
}

pub struct BlakeInteractionSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub round: InteractionEntryVar<30>,
    pub g: InteractionEntryVar<9>,
    pub sigma: InteractionEntryVar<1>,
    pub triple_xor_32: InteractionEntryVar<5>,
    pub verify_bitwise_xor_12: InteractionEntryVar<8>,
}

pub struct RangeChecksInteractionSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: InteractionEntryVar<1>,
    pub range_check_8: InteractionEntryVar<1>,
    pub range_check_11: InteractionEntryVar<1>,
    pub range_check_12: InteractionEntryVar<1>,
    pub range_check_18: InteractionEntryVar<1>,
    pub range_check_18_b: InteractionEntryVar<1>,
    pub range_check_20: InteractionEntryVar<1>,
    pub range_check_20_b: InteractionEntryVar<1>,
    pub range_check_20_c: InteractionEntryVar<1>,
    pub range_check_20_d: InteractionEntryVar<1>,
    pub range_check_20_e: InteractionEntryVar<1>,
    pub range_check_20_f: InteractionEntryVar<1>,
    pub range_check_20_g: InteractionEntryVar<1>,
    pub range_check_20_h: InteractionEntryVar<1>,
    pub range_check_4_3: InteractionEntryVar<1>,
    pub range_check_4_4: InteractionEntryVar<1>,
    pub range_check_5_4: InteractionEntryVar<1>,
    pub range_check_9_9: InteractionEntryVar<1>,
    pub range_check_9_9_b: InteractionEntryVar<1>,
    pub range_check_9_9_c: InteractionEntryVar<1>,
    pub range_check_9_9_d: InteractionEntryVar<1>,
    pub range_check_9_9_e: InteractionEntryVar<1>,
    pub range_check_9_9_f: InteractionEntryVar<1>,
    pub range_check_9_9_g: InteractionEntryVar<1>,
    pub range_check_9_9_h: InteractionEntryVar<1>,
    pub range_check_7_2_5: InteractionEntryVar<1>,
    pub range_check_3_6_6_3: InteractionEntryVar<1>,
    pub range_check_4_4_4_4: InteractionEntryVar<1>,
    pub range_check_3_3_3_3_3: InteractionEntryVar<1>,
}

pub struct VerifyBitwiseInteractionSampleResultVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: InteractionEntryVar<1>,
    pub verify_bitwise_xor_7: InteractionEntryVar<1>,
    pub verify_bitwise_xor_8: InteractionEntryVar<1>,
    pub verify_bitwise_xor_8_b: InteractionEntryVar<1>,
    pub verify_bitwise_xor_9: InteractionEntryVar<1>,
}

/// Helper function to allocate InteractionEntryVar<N> from sampled_values[2]
fn allocate_interaction_entry<const N: usize>(
    sampled_values: &Vec<Vec<QM31Var>>,
    offset: &mut usize,
) -> InteractionEntryVar<N> {
    let mut data = std::array::from_fn(|i| {
        let idx = *offset + 4 * i;
        [
            sampled_values[idx][0].clone(),
            sampled_values[idx + 1][0].clone(),
            sampled_values[idx + 2][0].clone(),
            sampled_values[idx + 3][0].clone(),
        ]
    });

    let last = *offset + 4 * (N - 1);
    let presum = [
        sampled_values[last][0].clone(),
        sampled_values[last + 1][0].clone(),
        sampled_values[last + 2][0].clone(),
        sampled_values[last + 3][0].clone(),
    ];
    // fix the last one
    data[N - 1] = [
        sampled_values[last][1].clone(),
        sampled_values[last + 1][1].clone(),
        sampled_values[last + 2][1].clone(),
        sampled_values[last + 3][1].clone(),
    ];

    *offset += 4 * N;

    InteractionEntryVar { data, presum }
}

impl InteractionSampleResultVar {
    pub fn new(cs: &ConstraintSystemRef, sampled_values: &Vec<Vec<QM31Var>>) -> Self {
        let mut offset = 0;

        // Allocate in the exact order as defined in InteractionSampleResultVar
        let opcodes = allocate_opcodes_interaction(cs, sampled_values, &mut offset);
        let verify_instruction = allocate_interaction_entry::<3>(sampled_values, &mut offset);
        let blake = allocate_blake_interaction(cs, sampled_values, &mut offset);
        let range_check_128_builtin = allocate_interaction_entry::<1>(sampled_values, &mut offset);
        let memory_address_to_id = allocate_interaction_entry::<8>(sampled_values, &mut offset);
        let memory_id_to_big_big = allocate_interaction_entry::<8>(sampled_values, &mut offset);
        let memory_id_to_big_small = allocate_interaction_entry::<3>(sampled_values, &mut offset);
        let range_checks = allocate_range_checks_interaction(cs, sampled_values, &mut offset);
        let verify_bitwise = allocate_verify_bitwise_interaction(cs, sampled_values, &mut offset);

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

/// Allocate OpcodesInteractionSampleResultVar from sampled_values[2]
fn allocate_opcodes_interaction(
    cs: &ConstraintSystemRef,
    sampled_values: &Vec<Vec<QM31Var>>,
    offset: &mut usize,
) -> OpcodesInteractionSampleResultVar {
    OpcodesInteractionSampleResultVar {
        cs: cs.clone(),
        add: allocate_interaction_entry::<5>(sampled_values, offset),
        add_small: allocate_interaction_entry::<5>(sampled_values, offset),
        add_ap: allocate_interaction_entry::<4>(sampled_values, offset),
        assert_eq: allocate_interaction_entry::<3>(sampled_values, offset),
        assert_eq_imm: allocate_interaction_entry::<3>(sampled_values, offset),
        assert_eq_double_deref: allocate_interaction_entry::<4>(sampled_values, offset),
        blake: allocate_interaction_entry::<37>(sampled_values, offset),
        call: allocate_interaction_entry::<5>(sampled_values, offset),
        call_rel_imm: allocate_interaction_entry::<5>(sampled_values, offset),
        jnz: allocate_interaction_entry::<3>(sampled_values, offset),
        jnz_taken: allocate_interaction_entry::<4>(sampled_values, offset),
        jump_rel: allocate_interaction_entry::<3>(sampled_values, offset),
        jump_rel_imm: allocate_interaction_entry::<3>(sampled_values, offset),
        mul: allocate_interaction_entry::<19>(sampled_values, offset),
        mul_small: allocate_interaction_entry::<6>(sampled_values, offset),
        qm31: allocate_interaction_entry::<6>(sampled_values, offset),
        ret: allocate_interaction_entry::<4>(sampled_values, offset),
    }
}

/// Allocate BlakeInteractionSampleResultVar from sampled_values[2]
fn allocate_blake_interaction(
    cs: &ConstraintSystemRef,
    sampled_values: &Vec<Vec<QM31Var>>,
    offset: &mut usize,
) -> BlakeInteractionSampleResultVar {
    BlakeInteractionSampleResultVar {
        cs: cs.clone(),
        round: allocate_interaction_entry::<30>(sampled_values, offset),
        g: allocate_interaction_entry::<9>(sampled_values, offset),
        sigma: allocate_interaction_entry::<1>(sampled_values, offset),
        triple_xor_32: allocate_interaction_entry::<5>(sampled_values, offset),
        verify_bitwise_xor_12: allocate_interaction_entry::<8>(sampled_values, offset),
    }
}

/// Allocate RangeChecksInteractionSampleResultVar from sampled_values[2]
fn allocate_range_checks_interaction(
    cs: &ConstraintSystemRef,
    sampled_values: &Vec<Vec<QM31Var>>,
    offset: &mut usize,
) -> RangeChecksInteractionSampleResultVar {
    RangeChecksInteractionSampleResultVar {
        cs: cs.clone(),
        range_check_6: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_8: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_11: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_12: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_18: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_18_b: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_b: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_c: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_d: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_e: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_f: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_g: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_20_h: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_4_3: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_4_4: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_5_4: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_b: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_c: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_d: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_e: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_f: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_g: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_9_9_h: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_7_2_5: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_3_6_6_3: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_4_4_4_4: allocate_interaction_entry::<1>(sampled_values, offset),
        range_check_3_3_3_3_3: allocate_interaction_entry::<1>(sampled_values, offset),
    }
}

/// Allocate VerifyBitwiseInteractionSampleResultVar from sampled_values[2]
fn allocate_verify_bitwise_interaction(
    cs: &ConstraintSystemRef,
    sampled_values: &Vec<Vec<QM31Var>>,
    offset: &mut usize,
) -> VerifyBitwiseInteractionSampleResultVar {
    VerifyBitwiseInteractionSampleResultVar {
        cs: cs.clone(),
        verify_bitwise_xor_4: allocate_interaction_entry::<1>(sampled_values, offset),
        verify_bitwise_xor_7: allocate_interaction_entry::<1>(sampled_values, offset),
        verify_bitwise_xor_8: allocate_interaction_entry::<1>(sampled_values, offset),
        verify_bitwise_xor_8_b: allocate_interaction_entry::<1>(sampled_values, offset),
        verify_bitwise_xor_9: allocate_interaction_entry::<1>(sampled_values, offset),
    }
}

pub struct InteractionQuotientConstantsEntryVar<const N: usize> {
    pub data: [[[CM31Var; 2]; SECURE_EXTENSION_DEGREE]; N],
    pub presum: [[CM31Var; 2]; SECURE_EXTENSION_DEGREE],
    pub shifted_point: CirclePointQM31Var,
}

pub struct InteractionQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesInteractionQuotientConstantsVar,
    pub verify_instruction: InteractionQuotientConstantsEntryVar<3>,
    pub blake: BlakeInteractionQuotientConstantsVar,
    pub range_check_128_builtin: InteractionQuotientConstantsEntryVar<1>,
    pub memory_address_to_id: InteractionQuotientConstantsEntryVar<8>,
    pub memory_id_to_big_big: InteractionQuotientConstantsEntryVar<8>,
    pub memory_id_to_big_small: InteractionQuotientConstantsEntryVar<3>,
    pub range_checks: RangeChecksInteractionQuotientConstantsVar,
    pub verify_bitwise: VerifyBitwiseInteractionQuotientConstantsVar,
}

impl InteractionQuotientConstantsVar {
    pub fn new(
        claim: &CairoClaimVar,
        oods_point: &CirclePointQM31Var,
        sample_result: &InteractionSampleResultVar,
        shifted_points: &ObliviousMapVar<CirclePointQM31Var>,
    ) -> Self {
        let cs = oods_point.cs();
        Self {
            cs: cs.clone(),
            opcodes: OpcodesInteractionQuotientConstantsVar::new(
                &claim.opcode_claim,
                oods_point,
                shifted_points,
                &sample_result.opcodes,
            ),
            verify_instruction: InteractionQuotientConstantsEntryVar::new(
                &claim.verify_instruction,
                oods_point,
                shifted_points,
                &sample_result.verify_instruction,
            ),
            blake: BlakeInteractionQuotientConstantsVar::new(
                &claim.blake_context,
                oods_point,
                shifted_points,
                &sample_result.blake,
            ),
            range_check_128_builtin: InteractionQuotientConstantsEntryVar::new(
                &claim.builtins.range_check_128_builtin_log_size,
                oods_point,
                shifted_points,
                &sample_result.range_check_128_builtin,
            ),
            memory_address_to_id: InteractionQuotientConstantsEntryVar::new(
                &claim.memory_address_to_id,
                oods_point,
                shifted_points,
                &sample_result.memory_address_to_id,
            ),
            memory_id_to_big_big: InteractionQuotientConstantsEntryVar::new(
                &claim.memory_id_to_value.big_log_size,
                oods_point,
                shifted_points,
                &sample_result.memory_id_to_big_big,
            ),
            memory_id_to_big_small: InteractionQuotientConstantsEntryVar::new(
                &claim.memory_id_to_value.small_log_size,
                oods_point,
                shifted_points,
                &sample_result.memory_id_to_big_small,
            ),
            range_checks: RangeChecksInteractionQuotientConstantsVar::new(
                oods_point,
                shifted_points,
                &sample_result.range_checks,
            ),
            verify_bitwise: VerifyBitwiseInteractionQuotientConstantsVar::new(
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise,
            ),
        }
    }
}

pub struct OpcodesInteractionQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub add: InteractionQuotientConstantsEntryVar<5>,
    pub add_small: InteractionQuotientConstantsEntryVar<5>,
    pub add_ap: InteractionQuotientConstantsEntryVar<4>,
    pub assert_eq: InteractionQuotientConstantsEntryVar<3>,
    pub assert_eq_imm: InteractionQuotientConstantsEntryVar<3>,
    pub assert_eq_double_deref: InteractionQuotientConstantsEntryVar<4>,
    pub blake: InteractionQuotientConstantsEntryVar<37>,
    pub call: InteractionQuotientConstantsEntryVar<5>,
    pub call_rel_imm: InteractionQuotientConstantsEntryVar<5>,
    pub jnz: InteractionQuotientConstantsEntryVar<3>,
    pub jnz_taken: InteractionQuotientConstantsEntryVar<4>,
    pub jump_rel: InteractionQuotientConstantsEntryVar<3>,
    pub jump_rel_imm: InteractionQuotientConstantsEntryVar<3>,
    pub mul: InteractionQuotientConstantsEntryVar<19>,
    pub mul_small: InteractionQuotientConstantsEntryVar<6>,
    pub qm31: InteractionQuotientConstantsEntryVar<6>,
    pub ret: InteractionQuotientConstantsEntryVar<4>,
}

impl OpcodesInteractionQuotientConstantsVar {
    pub fn new(
        claim: &OpcodeClaimVar,
        oods_point: &CirclePointQM31Var,
        shifted_points: &ObliviousMapVar<CirclePointQM31Var>,
        sample_result: &OpcodesInteractionSampleResultVar,
    ) -> Self {
        Self {
            cs: sample_result.cs.clone(),
            add: InteractionQuotientConstantsEntryVar::new(
                &claim.add,
                oods_point,
                shifted_points,
                &sample_result.add,
            ),
            add_small: InteractionQuotientConstantsEntryVar::new(
                &claim.add_small,
                oods_point,
                shifted_points,
                &sample_result.add_small,
            ),
            add_ap: InteractionQuotientConstantsEntryVar::new(
                &claim.add_ap,
                oods_point,
                shifted_points,
                &sample_result.add_ap,
            ),
            assert_eq: InteractionQuotientConstantsEntryVar::new(
                &claim.assert_eq,
                oods_point,
                shifted_points,
                &sample_result.assert_eq,
            ),
            assert_eq_imm: InteractionQuotientConstantsEntryVar::new(
                &claim.assert_eq_imm,
                oods_point,
                shifted_points,
                &sample_result.assert_eq_imm,
            ),
            assert_eq_double_deref: InteractionQuotientConstantsEntryVar::new(
                &claim.assert_eq_double_deref,
                oods_point,
                shifted_points,
                &sample_result.assert_eq_double_deref,
            ),
            blake: InteractionQuotientConstantsEntryVar::new(
                &claim.blake,
                oods_point,
                shifted_points,
                &sample_result.blake,
            ),
            call: InteractionQuotientConstantsEntryVar::new(
                &claim.call,
                oods_point,
                shifted_points,
                &sample_result.call,
            ),
            call_rel_imm: InteractionQuotientConstantsEntryVar::new(
                &claim.call_rel_imm,
                oods_point,
                shifted_points,
                &sample_result.call_rel_imm,
            ),
            jnz: InteractionQuotientConstantsEntryVar::new(
                &claim.jnz,
                oods_point,
                shifted_points,
                &sample_result.jnz,
            ),
            jnz_taken: InteractionQuotientConstantsEntryVar::new(
                &claim.jnz_taken,
                oods_point,
                shifted_points,
                &sample_result.jnz_taken,
            ),
            jump_rel: InteractionQuotientConstantsEntryVar::new(
                &claim.jump_rel,
                oods_point,
                shifted_points,
                &sample_result.jump_rel,
            ),
            jump_rel_imm: InteractionQuotientConstantsEntryVar::new(
                &claim.jump_rel_imm,
                oods_point,
                shifted_points,
                &sample_result.jump_rel_imm,
            ),
            mul: InteractionQuotientConstantsEntryVar::new(
                &claim.mul,
                oods_point,
                shifted_points,
                &sample_result.mul,
            ),
            mul_small: InteractionQuotientConstantsEntryVar::new(
                &claim.mul_small,
                oods_point,
                shifted_points,
                &sample_result.mul_small,
            ),
            qm31: InteractionQuotientConstantsEntryVar::new(
                &claim.qm31,
                oods_point,
                shifted_points,
                &sample_result.qm31,
            ),
            ret: InteractionQuotientConstantsEntryVar::new(
                &claim.ret,
                oods_point,
                shifted_points,
                &sample_result.ret,
            ),
        }
    }
}

pub struct BlakeInteractionQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub round: InteractionQuotientConstantsEntryVar<30>,
    pub g: InteractionQuotientConstantsEntryVar<9>,
    pub sigma: InteractionQuotientConstantsEntryVar<1>,
    pub triple_xor_32: InteractionQuotientConstantsEntryVar<5>,
    pub verify_bitwise_xor_12: InteractionQuotientConstantsEntryVar<8>,
}

impl BlakeInteractionQuotientConstantsVar {
    pub fn new(
        claim: &BlakeContextClaimVar,
        oods_point: &CirclePointQM31Var,
        shifted_points: &ObliviousMapVar<CirclePointQM31Var>,
        sample_result: &BlakeInteractionSampleResultVar,
    ) -> Self {
        Self {
            cs: sample_result.cs.clone(),
            round: InteractionQuotientConstantsEntryVar::new(
                &claim.blake_round,
                oods_point,
                shifted_points,
                &sample_result.round,
            ),
            g: InteractionQuotientConstantsEntryVar::new(
                &claim.blake_g,
                oods_point,
                shifted_points,
                &sample_result.g,
            ),
            sigma: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::blake_round_sigma::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.sigma,
            ),
            triple_xor_32: InteractionQuotientConstantsEntryVar::new(
                &claim.triple_xor_32,
                oods_point,
                shifted_points,
                &sample_result.triple_xor_32,
            ),
            verify_bitwise_xor_12: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise_xor_12,
            ),
        }
    }
}
pub struct RangeChecksInteractionQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_8: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_11: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_12: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_18: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_18_b: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_b: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_c: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_d: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_e: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_f: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_g: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_20_h: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_4_3: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_4_4: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_5_4: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_b: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_c: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_d: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_e: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_f: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_g: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_9_9_h: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_7_2_5: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_3_6_6_3: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_4_4_4_4: InteractionQuotientConstantsEntryVar<1>,
    pub range_check_3_3_3_3_3: InteractionQuotientConstantsEntryVar<1>,
}

impl RangeChecksInteractionQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        shifted_points: &ObliviousMapVar<CirclePointQM31Var>,
        sample_result: &RangeChecksInteractionSampleResultVar,
    ) -> Self {
        Self {
            cs: sample_result.cs.clone(),
            range_check_6: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_6::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_6,
            ),
            range_check_8: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_8::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_8,
            ),
            range_check_11: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_11::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_11,
            ),
            range_check_12: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_12::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_12,
            ),
            range_check_18: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_18::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_18,
            ),
            range_check_18_b: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_18_b::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_18_b,
            ),
            range_check_20: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20,
            ),
            range_check_20_b: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_b::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_b,
            ),
            range_check_20_c: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_c::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_c,
            ),
            range_check_20_d: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_d::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_d,
            ),
            range_check_20_e: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_e::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_e,
            ),
            range_check_20_f: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_f::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_f,
            ),
            range_check_20_g: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_g::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_g,
            ),
            range_check_20_h: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_20_h::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_20_h,
            ),
            range_check_4_3: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_4_3::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_4_3,
            ),
            range_check_4_4: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_4_4::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_4_4,
            ),
            range_check_5_4: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_5_4::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_5_4,
            ),
            range_check_9_9: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9,
            ),
            range_check_9_9_b: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_b::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_b,
            ),
            range_check_9_9_c: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_c::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_c,
            ),
            range_check_9_9_d: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_d::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_d,
            ),
            range_check_9_9_e: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_e::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_e,
            ),
            range_check_9_9_f: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_f::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_f,
            ),
            range_check_9_9_g: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_g::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_g,
            ),
            range_check_9_9_h: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_9_9_h::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_9_9_h,
            ),
            range_check_7_2_5: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_7_2_5::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_7_2_5,
            ),
            range_check_3_6_6_3: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_3_6_6_3::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_3_6_6_3,
            ),
            range_check_4_4_4_4: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_4_4_4_4::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_4_4_4_4,
            ),
            range_check_3_3_3_3_3: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::range_check_3_3_3_3_3::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.range_check_3_3_3_3_3,
            ),
        }
    }
}

pub struct VerifyBitwiseInteractionQuotientConstantsVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: InteractionQuotientConstantsEntryVar<1>,
    pub verify_bitwise_xor_7: InteractionQuotientConstantsEntryVar<1>,
    pub verify_bitwise_xor_8: InteractionQuotientConstantsEntryVar<1>,
    pub verify_bitwise_xor_8_b: InteractionQuotientConstantsEntryVar<1>,
    pub verify_bitwise_xor_9: InteractionQuotientConstantsEntryVar<1>,
}

impl VerifyBitwiseInteractionQuotientConstantsVar {
    pub fn new(
        oods_point: &CirclePointQM31Var,
        shifted_points: &ObliviousMapVar<CirclePointQM31Var>,
        sample_result: &VerifyBitwiseInteractionSampleResultVar,
    ) -> Self {
        Self {
            cs: sample_result.cs.clone(),
            verify_bitwise_xor_4: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::verify_bitwise_xor_4::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise_xor_4,
            ),
            verify_bitwise_xor_7: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::verify_bitwise_xor_7::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise_xor_7,
            ),
            verify_bitwise_xor_8: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::verify_bitwise_xor_8::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise_xor_8,
            ),
            verify_bitwise_xor_8_b: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::verify_bitwise_xor_8_b::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise_xor_8_b,
            ),
            verify_bitwise_xor_9: InteractionQuotientConstantsEntryVar::new_fixed_log_size(
                cairo_air::components::verify_bitwise_xor_9::LOG_SIZE,
                oods_point,
                shifted_points,
                &sample_result.verify_bitwise_xor_9,
            ),
        }
    }
}

impl<const N: usize> InteractionQuotientConstantsEntryVar<N> {
    pub fn new(
        log_size: &LogSizeVar,
        oods_point: &CirclePointQM31Var,
        oods_shifted_point_map: &ObliviousMapVar<CirclePointQM31Var>,
        entry: &InteractionEntryVar<N>,
    ) -> Self {
        let data = std::array::from_fn(|i| {
            std::array::from_fn(|j| {
                complex_conjugate_line_coeffs_var(oods_point, &entry.data[i][j])
            })
        });

        let shifted_point = oods_shifted_point_map.select(log_size);

        let presum = std::array::from_fn(|i| {
            complex_conjugate_line_coeffs_var(&shifted_point, &entry.presum[i])
        });

        Self {
            data,
            presum,
            shifted_point,
        }
    }

    pub fn new_fixed_log_size(
        log_size: u32,
        oods_point: &CirclePointQM31Var,
        oods_shifted_point_map: &ObliviousMapVar<CirclePointQM31Var>,
        entry: &InteractionEntryVar<N>,
    ) -> Self {
        let data = std::array::from_fn(|i| {
            std::array::from_fn(|j| {
                complex_conjugate_line_coeffs_var(oods_point, &entry.data[i][j])
            })
        });

        let shifted_point = oods_shifted_point_map.0.get(&log_size).unwrap().clone();

        let presum = std::array::from_fn(|i| {
            complex_conjugate_line_coeffs_var(&shifted_point, &entry.presum[i])
        });

        Self {
            data,
            presum,
            shifted_point,
        }
    }
}

pub fn compute_interaction_answers_without_shift(
    num_queries: usize,
    answer_accumulator: &mut Vec<AnswerAccumulator>,
    oods_point_y: &CM31Var,
    domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
    denominator_inverses_with_oods_point: &IndexMap<u32, Vec<CM31Var>>,
    query_result: &CairoDecommitmentResultsVar,
    quotient_constants: &InteractionQuotientConstantsVar,
    claim: &CairoClaimVar,
) {
    fn update<const N: usize>(
        answer_accumulator: &mut AnswerAccumulator,
        domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
        denominator_inverses_with_oods_point: &IndexMap<u32, Vec<CM31Var>>,
        log_size: &LogSizeVar,
        query: &[QM31Var],
        quotient_constants: &InteractionQuotientConstantsEntryVar<N>,
        idx: usize,
        oods_point_y: &CM31Var,
    ) {
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

        let mut update = vec![];
        quotient_constants
            .data
            .iter()
            .zip_eq(query.iter())
            .for_each(|(quotient_constants, query)| {
                let query = query.decompose_m31();
                for (quotient_constant, query) in quotient_constants.iter().zip_eq(query.iter()) {
                    update.push(
                        &denominator_inverse
                            * &(&(&(oods_point_y * query) - &(&quotient_constant[0] * &y))
                                - &quotient_constant[1]),
                    );
                }
            });
        answer_accumulator.update(log_size, &update);
    }

    fn update_fixed_log_size<const N: usize>(
        answer_accumulator: &mut AnswerAccumulator,
        domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
        denominator_inverses_with_oods_point: &IndexMap<u32, Vec<CM31Var>>,
        log_size: u32,
        query: &[QM31Var],
        quotient_constants: &InteractionQuotientConstantsEntryVar<N>,
        idx: usize,
        oods_point_y: &CM31Var,
    ) {
        let query_point = &domain_points.get(&(log_size + 1)).unwrap()[idx];
        let denominator_inverse = &denominator_inverses_with_oods_point
            .get(&(log_size + 1))
            .unwrap()[idx];
        let mut update = vec![];
        quotient_constants
            .data
            .iter()
            .zip_eq(query.iter())
            .for_each(|(quotient_constants, query)| {
                let query = query.decompose_m31();
                for (quotient_constant, query) in quotient_constants.iter().zip_eq(query.iter()) {
                    update.push(
                        denominator_inverse
                            * &(&(&(oods_point_y * query)
                                - &(&quotient_constant[0] * &query_point.y))
                                - &quotient_constant[1]),
                    );
                }
            });
        answer_accumulator.update_fix_log_size(log_size as usize, &update);
    }

    for idx in 0..num_queries {
        let answer_accumulator = &mut answer_accumulator[idx];
        let query_result = &query_result[idx].interaction_query_result;

        // opcodes
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.add,
            &query_result.opcodes.add,
            &quotient_constants.opcodes.add,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.add_small,
            &query_result.opcodes.add_small,
            &quotient_constants.opcodes.add_small,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.add_ap,
            &query_result.opcodes.add_ap,
            &quotient_constants.opcodes.add_ap,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.assert_eq,
            &query_result.opcodes.assert_eq,
            &quotient_constants.opcodes.assert_eq,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.assert_eq_imm,
            &query_result.opcodes.assert_eq_imm,
            &quotient_constants.opcodes.assert_eq_imm,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.assert_eq_double_deref,
            &query_result.opcodes.assert_eq_double_deref,
            &quotient_constants.opcodes.assert_eq_double_deref,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.blake,
            &query_result.opcodes.blake,
            &quotient_constants.opcodes.blake,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.call,
            &query_result.opcodes.call,
            &quotient_constants.opcodes.call,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.call_rel_imm,
            &query_result.opcodes.call_rel_imm,
            &quotient_constants.opcodes.call_rel_imm,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.jnz,
            &query_result.opcodes.jnz,
            &quotient_constants.opcodes.jnz,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.jnz_taken,
            &query_result.opcodes.jnz_taken,
            &quotient_constants.opcodes.jnz_taken,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.jump_rel,
            &query_result.opcodes.jump_rel,
            &quotient_constants.opcodes.jump_rel,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.jump_rel_imm,
            &query_result.opcodes.jump_rel_imm,
            &quotient_constants.opcodes.jump_rel_imm,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.mul,
            &query_result.opcodes.mul,
            &quotient_constants.opcodes.mul,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.mul_small,
            &query_result.opcodes.mul_small,
            &quotient_constants.opcodes.mul_small,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.qm31,
            &query_result.opcodes.qm31,
            &quotient_constants.opcodes.qm31,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.opcode_claim.ret,
            &query_result.opcodes.ret,
            &quotient_constants.opcodes.ret,
            idx,
            &oods_point_y,
        );

        // verify_instruction
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.verify_instruction,
            &query_result.verify_instruction,
            &quotient_constants.verify_instruction,
            idx,
            &oods_point_y,
        );

        // blake
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.blake_context.blake_round,
            &query_result.blake.round,
            &quotient_constants.blake.round,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.blake_context.blake_g,
            &query_result.blake.g,
            &quotient_constants.blake.g,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::blake_round_sigma::LOG_SIZE,
            &query_result.blake.sigma,
            &quotient_constants.blake.sigma,
            idx,
            &oods_point_y,
        );
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.blake_context.triple_xor_32,
            &query_result.blake.triple_xor_32,
            &quotient_constants.blake.triple_xor_32,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
            &query_result.blake.verify_bitwise_xor_12,
            &quotient_constants.blake.verify_bitwise_xor_12,
            idx,
            &oods_point_y,
        );

        // range_check_128_builtin
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.builtins.range_check_128_builtin_log_size,
            &query_result.range_check_128_builtin,
            &quotient_constants.range_check_128_builtin,
            idx,
            &oods_point_y,
        );

        // memory_address_to_id
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.memory_address_to_id,
            &query_result.memory_address_to_id,
            &quotient_constants.memory_address_to_id,
            idx,
            &oods_point_y,
        );

        // memory_id_to_big_big
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.memory_id_to_value.big_log_size,
            &query_result.memory_id_to_big_big,
            &quotient_constants.memory_id_to_big_big,
            idx,
            &oods_point_y,
        );

        // memory_id_to_big_small
        update(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            &claim.memory_id_to_value.small_log_size,
            &query_result.memory_id_to_big_small,
            &quotient_constants.memory_id_to_big_small,
            idx,
            &oods_point_y,
        );

        // range_checks
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_6::LOG_SIZE,
            &query_result.range_checks.range_check_6,
            &quotient_constants.range_checks.range_check_6,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_8::LOG_SIZE,
            &query_result.range_checks.range_check_8,
            &quotient_constants.range_checks.range_check_8,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_11::LOG_SIZE,
            &query_result.range_checks.range_check_11,
            &quotient_constants.range_checks.range_check_11,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_12::LOG_SIZE,
            &query_result.range_checks.range_check_12,
            &quotient_constants.range_checks.range_check_12,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_18::LOG_SIZE,
            &query_result.range_checks.range_check_18,
            &quotient_constants.range_checks.range_check_18,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_18_b::LOG_SIZE,
            &query_result.range_checks.range_check_18_b,
            &quotient_constants.range_checks.range_check_18_b,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20::LOG_SIZE,
            &query_result.range_checks.range_check_20,
            &quotient_constants.range_checks.range_check_20,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_b::LOG_SIZE,
            &query_result.range_checks.range_check_20_b,
            &quotient_constants.range_checks.range_check_20_b,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_c::LOG_SIZE,
            &query_result.range_checks.range_check_20_c,
            &quotient_constants.range_checks.range_check_20_c,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_d::LOG_SIZE,
            &query_result.range_checks.range_check_20_d,
            &quotient_constants.range_checks.range_check_20_d,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_e::LOG_SIZE,
            &query_result.range_checks.range_check_20_e,
            &quotient_constants.range_checks.range_check_20_e,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_f::LOG_SIZE,
            &query_result.range_checks.range_check_20_f,
            &quotient_constants.range_checks.range_check_20_f,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_g::LOG_SIZE,
            &query_result.range_checks.range_check_20_g,
            &quotient_constants.range_checks.range_check_20_g,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_20_h::LOG_SIZE,
            &query_result.range_checks.range_check_20_h,
            &quotient_constants.range_checks.range_check_20_h,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_4_3::LOG_SIZE,
            &query_result.range_checks.range_check_4_3,
            &quotient_constants.range_checks.range_check_4_3,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_4_4::LOG_SIZE,
            &query_result.range_checks.range_check_4_4,
            &quotient_constants.range_checks.range_check_4_4,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_5_4::LOG_SIZE,
            &query_result.range_checks.range_check_5_4,
            &quotient_constants.range_checks.range_check_5_4,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9::LOG_SIZE,
            &query_result.range_checks.range_check_9_9,
            &quotient_constants.range_checks.range_check_9_9,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_b::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_b,
            &quotient_constants.range_checks.range_check_9_9_b,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_c::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_c,
            &quotient_constants.range_checks.range_check_9_9_c,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_d::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_d,
            &quotient_constants.range_checks.range_check_9_9_d,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_e::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_e,
            &quotient_constants.range_checks.range_check_9_9_e,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_f::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_f,
            &quotient_constants.range_checks.range_check_9_9_f,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_g::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_g,
            &quotient_constants.range_checks.range_check_9_9_g,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_9_9_h::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_h,
            &quotient_constants.range_checks.range_check_9_9_h,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_7_2_5::LOG_SIZE,
            &query_result.range_checks.range_check_7_2_5,
            &quotient_constants.range_checks.range_check_7_2_5,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_3_6_6_3::LOG_SIZE,
            &query_result.range_checks.range_check_3_6_6_3,
            &quotient_constants.range_checks.range_check_3_6_6_3,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_4_4_4_4::LOG_SIZE,
            &query_result.range_checks.range_check_4_4_4_4,
            &quotient_constants.range_checks.range_check_4_4_4_4,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::range_check_3_3_3_3_3::LOG_SIZE,
            &query_result.range_checks.range_check_3_3_3_3_3,
            &quotient_constants.range_checks.range_check_3_3_3_3_3,
            idx,
            &oods_point_y,
        );

        // verify_bitwise
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::verify_bitwise_xor_4::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_4,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_4,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::verify_bitwise_xor_7::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_7,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_7,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::verify_bitwise_xor_8::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_8,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_8,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::verify_bitwise_xor_8_b::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_8_b,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_8_b,
            idx,
            &oods_point_y,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            &denominator_inverses_with_oods_point,
            cairo_air::components::verify_bitwise_xor_9::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_9,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_9,
            idx,
            &oods_point_y,
        );
    }
}

pub fn compute_interaction_answers_shift_only(
    num_queries: usize,
    answer_accumulator: &mut Vec<AnswerAccumulator>,
    domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
    query_result: &CairoDecommitmentResultsVar,
    quotient_constants: &InteractionQuotientConstantsVar,
    claim: &CairoClaimVar,
) {
    fn update<const N: usize>(
        answer_accumulator: &mut AnswerAccumulator,
        domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
        log_size: &LogSizeVar,
        query: &[QM31Var],
        quotient_constants: &InteractionQuotientConstantsEntryVar<N>,
        idx: usize,
    ) {
        let mut x = M31Var::zero(&log_size.cs());
        let mut y = M31Var::zero(&log_size.cs());

        for i in (LOG_N_LANES + 1)..=(MAX_SEQUENCE_LOG_SIZE + 1) {
            let bit = log_size.bitmap.get(&(i - 1)).unwrap();
            x = &x + &(&bit.0 * &domain_points.get(&i).unwrap()[idx].x);
            y = &y + &(&bit.0 * &domain_points.get(&i).unwrap()[idx].y);
        }

        let shifted_point = quotient_constants.shifted_point.clone();
        let [prx, pix] = shifted_point.x.decompose_cm31();
        let [pry, piy] = shifted_point.y.decompose_cm31();
        let denominator_inverse = (&(&(&prx - &x) * &piy) - &(&(&pry - &y) * &pix)).inv();

        let mut update = vec![];

        let query = query.last().unwrap().decompose_m31();
        for (quotient_constant, query) in quotient_constants.presum.iter().zip_eq(query.iter()) {
            update.push(
                &denominator_inverse
                    * &(&(&(&piy * query) - &(&quotient_constant[0] * &y)) - &quotient_constant[1]),
            );
        }
        answer_accumulator.update(log_size, &update);
    }

    fn update_fixed_log_size<const N: usize>(
        answer_accumulator: &mut AnswerAccumulator,
        domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
        log_size: u32,
        query: &[QM31Var],
        quotient_constants: &InteractionQuotientConstantsEntryVar<N>,
        idx: usize,
    ) {
        let query_point = &domain_points.get(&(log_size + 1)).unwrap()[idx];

        let shifted_point = quotient_constants.shifted_point.clone();
        let [prx, pix] = shifted_point.x.decompose_cm31();
        let [pry, piy] = shifted_point.y.decompose_cm31();
        let denominator_inverse =
            (&(&(&prx - &query_point.x) * &piy) - &(&(&pry - &query_point.y) * &pix)).inv();

        let mut update = vec![];

        let query = query.last().unwrap().decompose_m31();
        for (quotient_constant, query) in quotient_constants.presum.iter().zip_eq(query.iter()) {
            update.push(
                &denominator_inverse
                    * &(&(&(&piy * query) - &(&quotient_constant[0] * &query_point.y))
                        - &quotient_constant[1]),
            );
        }
        answer_accumulator.update_fix_log_size(log_size as usize, &update);
    }

    for idx in 0..num_queries {
        let answer_accumulator = &mut answer_accumulator[idx];
        let query_result = &query_result[idx].interaction_query_result;

        // opcodes
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.add,
            &query_result.opcodes.add,
            &quotient_constants.opcodes.add,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.add_small,
            &query_result.opcodes.add_small,
            &quotient_constants.opcodes.add_small,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.add_ap,
            &query_result.opcodes.add_ap,
            &quotient_constants.opcodes.add_ap,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.assert_eq,
            &query_result.opcodes.assert_eq,
            &quotient_constants.opcodes.assert_eq,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.assert_eq_imm,
            &query_result.opcodes.assert_eq_imm,
            &quotient_constants.opcodes.assert_eq_imm,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.assert_eq_double_deref,
            &query_result.opcodes.assert_eq_double_deref,
            &quotient_constants.opcodes.assert_eq_double_deref,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.blake,
            &query_result.opcodes.blake,
            &quotient_constants.opcodes.blake,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.call,
            &query_result.opcodes.call,
            &quotient_constants.opcodes.call,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.call_rel_imm,
            &query_result.opcodes.call_rel_imm,
            &quotient_constants.opcodes.call_rel_imm,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.jnz,
            &query_result.opcodes.jnz,
            &quotient_constants.opcodes.jnz,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.jnz_taken,
            &query_result.opcodes.jnz_taken,
            &quotient_constants.opcodes.jnz_taken,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.jump_rel,
            &query_result.opcodes.jump_rel,
            &quotient_constants.opcodes.jump_rel,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.jump_rel_imm,
            &query_result.opcodes.jump_rel_imm,
            &quotient_constants.opcodes.jump_rel_imm,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.mul,
            &query_result.opcodes.mul,
            &quotient_constants.opcodes.mul,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.mul_small,
            &query_result.opcodes.mul_small,
            &quotient_constants.opcodes.mul_small,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.qm31,
            &query_result.opcodes.qm31,
            &quotient_constants.opcodes.qm31,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.opcode_claim.ret,
            &query_result.opcodes.ret,
            &quotient_constants.opcodes.ret,
            idx,
        );

        // verify_instruction
        update(
            answer_accumulator,
            &domain_points,
            &claim.verify_instruction,
            &query_result.verify_instruction,
            &quotient_constants.verify_instruction,
            idx,
        );

        // blake
        update(
            answer_accumulator,
            &domain_points,
            &claim.blake_context.blake_round,
            &query_result.blake.round,
            &quotient_constants.blake.round,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.blake_context.blake_g,
            &query_result.blake.g,
            &quotient_constants.blake.g,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::blake_round_sigma::LOG_SIZE,
            &query_result.blake.sigma,
            &quotient_constants.blake.sigma,
            idx,
        );
        update(
            answer_accumulator,
            &domain_points,
            &claim.blake_context.triple_xor_32,
            &query_result.blake.triple_xor_32,
            &quotient_constants.blake.triple_xor_32,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
            &query_result.blake.verify_bitwise_xor_12,
            &quotient_constants.blake.verify_bitwise_xor_12,
            idx,
        );

        // range_check_128_builtin
        update(
            answer_accumulator,
            &domain_points,
            &claim.builtins.range_check_128_builtin_log_size,
            &query_result.range_check_128_builtin,
            &quotient_constants.range_check_128_builtin,
            idx,
        );

        // memory_address_to_id
        update(
            answer_accumulator,
            &domain_points,
            &claim.memory_address_to_id,
            &query_result.memory_address_to_id,
            &quotient_constants.memory_address_to_id,
            idx,
        );

        // memory_id_to_big_big
        update(
            answer_accumulator,
            &domain_points,
            &claim.memory_id_to_value.big_log_size,
            &query_result.memory_id_to_big_big,
            &quotient_constants.memory_id_to_big_big,
            idx,
        );

        // memory_id_to_big_small
        update(
            answer_accumulator,
            &domain_points,
            &claim.memory_id_to_value.small_log_size,
            &query_result.memory_id_to_big_small,
            &quotient_constants.memory_id_to_big_small,
            idx,
        );

        // range_checks
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_6::LOG_SIZE,
            &query_result.range_checks.range_check_6,
            &quotient_constants.range_checks.range_check_6,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_8::LOG_SIZE,
            &query_result.range_checks.range_check_8,
            &quotient_constants.range_checks.range_check_8,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_11::LOG_SIZE,
            &query_result.range_checks.range_check_11,
            &quotient_constants.range_checks.range_check_11,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_12::LOG_SIZE,
            &query_result.range_checks.range_check_12,
            &quotient_constants.range_checks.range_check_12,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_18::LOG_SIZE,
            &query_result.range_checks.range_check_18,
            &quotient_constants.range_checks.range_check_18,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_18_b::LOG_SIZE,
            &query_result.range_checks.range_check_18_b,
            &quotient_constants.range_checks.range_check_18_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20::LOG_SIZE,
            &query_result.range_checks.range_check_20,
            &quotient_constants.range_checks.range_check_20,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_b::LOG_SIZE,
            &query_result.range_checks.range_check_20_b,
            &quotient_constants.range_checks.range_check_20_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_c::LOG_SIZE,
            &query_result.range_checks.range_check_20_c,
            &quotient_constants.range_checks.range_check_20_c,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_d::LOG_SIZE,
            &query_result.range_checks.range_check_20_d,
            &quotient_constants.range_checks.range_check_20_d,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_e::LOG_SIZE,
            &query_result.range_checks.range_check_20_e,
            &quotient_constants.range_checks.range_check_20_e,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_f::LOG_SIZE,
            &query_result.range_checks.range_check_20_f,
            &quotient_constants.range_checks.range_check_20_f,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_g::LOG_SIZE,
            &query_result.range_checks.range_check_20_g,
            &quotient_constants.range_checks.range_check_20_g,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_20_h::LOG_SIZE,
            &query_result.range_checks.range_check_20_h,
            &quotient_constants.range_checks.range_check_20_h,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_4_3::LOG_SIZE,
            &query_result.range_checks.range_check_4_3,
            &quotient_constants.range_checks.range_check_4_3,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_4_4::LOG_SIZE,
            &query_result.range_checks.range_check_4_4,
            &quotient_constants.range_checks.range_check_4_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_5_4::LOG_SIZE,
            &query_result.range_checks.range_check_5_4,
            &quotient_constants.range_checks.range_check_5_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9::LOG_SIZE,
            &query_result.range_checks.range_check_9_9,
            &quotient_constants.range_checks.range_check_9_9,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_b::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_b,
            &quotient_constants.range_checks.range_check_9_9_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_c::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_c,
            &quotient_constants.range_checks.range_check_9_9_c,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_d::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_d,
            &quotient_constants.range_checks.range_check_9_9_d,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_e::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_e,
            &quotient_constants.range_checks.range_check_9_9_e,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_f::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_f,
            &quotient_constants.range_checks.range_check_9_9_f,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_g::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_g,
            &quotient_constants.range_checks.range_check_9_9_g,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_9_9_h::LOG_SIZE,
            &query_result.range_checks.range_check_9_9_h,
            &quotient_constants.range_checks.range_check_9_9_h,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_7_2_5::LOG_SIZE,
            &query_result.range_checks.range_check_7_2_5,
            &quotient_constants.range_checks.range_check_7_2_5,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_3_6_6_3::LOG_SIZE,
            &query_result.range_checks.range_check_3_6_6_3,
            &quotient_constants.range_checks.range_check_3_6_6_3,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_4_4_4_4::LOG_SIZE,
            &query_result.range_checks.range_check_4_4_4_4,
            &quotient_constants.range_checks.range_check_4_4_4_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::range_check_3_3_3_3_3::LOG_SIZE,
            &query_result.range_checks.range_check_3_3_3_3_3,
            &quotient_constants.range_checks.range_check_3_3_3_3_3,
            idx,
        );

        // verify_bitwise
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::verify_bitwise_xor_4::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_4,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_4,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::verify_bitwise_xor_7::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_7,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_7,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::verify_bitwise_xor_8::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_8,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_8,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::verify_bitwise_xor_8_b::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_8_b,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_8_b,
            idx,
        );
        update_fixed_log_size(
            answer_accumulator,
            &domain_points,
            cairo_air::components::verify_bitwise_xor_9::LOG_SIZE,
            &query_result.verify_bitwise.verify_bitwise_xor_9,
            &quotient_constants.verify_bitwise.verify_bitwise_xor_9,
            idx,
        );
    }
}
