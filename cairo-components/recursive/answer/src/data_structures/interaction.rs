use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
use circle_plonk_dsl_primitives::{
    oblivious_map::ObliviousMapVar, CM31Var, CirclePointQM31Var, LogSizeVar, QM31Var,
};
use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;

use crate::complex_conjugate_line_coeffs_var;

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
    pub data: [[[CM31Var; 3]; SECURE_EXTENSION_DEGREE]; N],
    pub presum: [[CM31Var; 3]; SECURE_EXTENSION_DEGREE],
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

        Self { data, presum }
    }
}
