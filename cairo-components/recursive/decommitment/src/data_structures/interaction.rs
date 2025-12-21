use cairo_air::components;
use cairo_plonk_dsl_data_structures::{BlakeContextClaimVar, CairoClaimVar, OpcodeClaimVar};
use cairo_plonk_dsl_hints::decommitment::{
    BlakeInteractionQueryResult, InteractionQueryResult, OpcodesInteractionQueryResult,
    RangeChecksInteractionQueryResult, VerifyBitwiseInteractionQueryResult,
};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{option::OptionVar, Poseidon2HalfVar, QM31Var};
use indexmap::IndexMap;

use crate::utils::ColumnsHasherQM31Var;

pub struct InteractionQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesInteractionQueryResultVar,
    pub verify_instruction: [QM31Var; 3],
    pub blake: BlakeInteractionQueryResultVar,
    pub range_check_128_builtin: [QM31Var; 1],
    pub memory_address_to_id: [QM31Var; 8],
    pub memory_id_to_big_big: [QM31Var; 8],
    pub memory_id_to_big_small: [QM31Var; 3],
    pub range_checks: RangeChecksInteractionQueryResultVar,
    pub verify_bitwise: VerifyBitwiseInteractionQueryResultVar,
}

impl Var for InteractionQueryResultVar {
    type Value = InteractionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for InteractionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            opcodes: AllocVar::new_variables(cs, &value.opcodes, mode),
            verify_instruction: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_instruction[i], mode)
            }),
            blake: AllocVar::new_variables(cs, &value.blake, mode),
            range_check_128_builtin: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_128_builtin[i], mode)
            }),
            memory_address_to_id: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.memory_address_to_id[i], mode)
            }),
            memory_id_to_big_big: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.memory_id_to_big_big[i], mode)
            }),
            memory_id_to_big_small: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.memory_id_to_big_small[i], mode)
            }),
            range_checks: AllocVar::new_variables(cs, &value.range_checks, mode),
            verify_bitwise: AllocVar::new_variables(cs, &value.verify_bitwise, mode),
        }
    }
}

impl InteractionQueryResultVar {
    pub fn compute_column_hashes(
        &self,
        claim: &CairoClaimVar,
    ) -> IndexMap<usize, OptionVar<Poseidon2HalfVar>> {
        let mut columns_hasher = ColumnsHasherQM31Var::new(&self.cs);
        self.opcodes
            .update_hashes(&mut columns_hasher, &claim.opcode_claim);
        columns_hasher.update(&claim.verify_instruction.m31, &self.verify_instruction);
        self.blake
            .update_hashes(&mut columns_hasher, &claim.blake_context);
        columns_hasher.update(
            &claim.builtins.range_check_128_builtin_log_size.m31,
            &self.range_check_128_builtin,
        );
        columns_hasher.update(&claim.memory_address_to_id.m31, &self.memory_address_to_id);
        columns_hasher.update(
            &claim.memory_id_to_value.big_log_size.m31,
            &self.memory_id_to_big_big,
        );
        columns_hasher.update(
            &claim.memory_id_to_value.small_log_size.m31,
            &self.memory_id_to_big_small,
        );
        self.range_checks.update_hashes(&mut columns_hasher);
        self.verify_bitwise.update_hashes(&mut columns_hasher);
        columns_hasher.finalize()
    }
}

pub struct OpcodesInteractionQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub add: [QM31Var; 5],
    pub add_small: [QM31Var; 5],
    pub add_ap: [QM31Var; 4],
    pub assert_eq: [QM31Var; 3],
    pub assert_eq_imm: [QM31Var; 3],
    pub assert_eq_double_deref: [QM31Var; 4],
    pub blake: [QM31Var; 37],
    pub call: [QM31Var; 5],
    pub call_rel_imm: [QM31Var; 5],
    pub jnz: [QM31Var; 3],
    pub jnz_taken: [QM31Var; 4],
    pub jump_rel: [QM31Var; 3],
    pub jump_rel_imm: [QM31Var; 3],
    pub mul: [QM31Var; 19],
    pub mul_small: [QM31Var; 6],
    pub qm31: [QM31Var; 6],
    pub ret: [QM31Var; 4],
}

impl Var for OpcodesInteractionQueryResultVar {
    type Value = OpcodesInteractionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for OpcodesInteractionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            add: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.add[i], mode)),
            add_small: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.add_small[i], mode)
            }),
            add_ap: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.add_ap[i], mode)),
            assert_eq: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.assert_eq[i], mode)
            }),
            assert_eq_imm: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.assert_eq_imm[i], mode)
            }),
            assert_eq_double_deref: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.assert_eq_double_deref[i], mode)
            }),
            blake: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.blake[i], mode)),
            call: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.call[i], mode)),
            call_rel_imm: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.call_rel_imm[i], mode)
            }),
            jnz: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.jnz[i], mode)),
            jnz_taken: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.jnz_taken[i], mode)
            }),
            jump_rel: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.jump_rel[i], mode)),
            jump_rel_imm: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.jump_rel_imm[i], mode)
            }),
            mul: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.mul[i], mode)),
            mul_small: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.mul_small[i], mode)
            }),
            qm31: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.qm31[i], mode)),
            ret: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.ret[i], mode)),
        }
    }
}

impl OpcodesInteractionQueryResultVar {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherQM31Var, claim: &OpcodeClaimVar) {
        columns_hasher.update(&claim.add.m31, &self.add);
        columns_hasher.update(&claim.add_small.m31, &self.add_small);
        columns_hasher.update(&claim.add_ap.m31, &self.add_ap);
        columns_hasher.update(&claim.assert_eq.m31, &self.assert_eq);
        columns_hasher.update(&claim.assert_eq_imm.m31, &self.assert_eq_imm);
        columns_hasher.update(
            &claim.assert_eq_double_deref.m31,
            &self.assert_eq_double_deref,
        );
        columns_hasher.update(&claim.blake.m31, &self.blake);
        columns_hasher.update(&claim.call.m31, &self.call);
        columns_hasher.update(&claim.call_rel_imm.m31, &self.call_rel_imm);
        columns_hasher.update(&claim.jnz.m31, &self.jnz);
        columns_hasher.update(&claim.jnz_taken.m31, &self.jnz_taken);
        columns_hasher.update(&claim.jump_rel.m31, &self.jump_rel);
        columns_hasher.update(&claim.jump_rel_imm.m31, &self.jump_rel_imm);
        columns_hasher.update(&claim.mul.m31, &self.mul);
        columns_hasher.update(&claim.mul_small.m31, &self.mul_small);
        columns_hasher.update(&claim.qm31.m31, &self.qm31);
        columns_hasher.update(&claim.ret.m31, &self.ret);
    }
}

pub struct BlakeInteractionQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub round: [QM31Var; 30],
    pub g: [QM31Var; 9],
    pub sigma: [QM31Var; 1],
    pub triple_xor_32: [QM31Var; 5],
    pub verify_bitwise_xor_12: [QM31Var; 8],
}

impl Var for BlakeInteractionQueryResultVar {
    type Value = BlakeInteractionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for BlakeInteractionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            round: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.round[i], mode)),
            g: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.g[i], mode)),
            sigma: std::array::from_fn(|i| QM31Var::new_variables(cs, &value.sigma[i], mode)),
            triple_xor_32: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.triple_xor_32[i], mode)
            }),
            verify_bitwise_xor_12: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_bitwise_xor_12[i], mode)
            }),
        }
    }
}

impl BlakeInteractionQueryResultVar {
    pub fn update_hashes(
        &self,
        columns_hasher: &mut ColumnsHasherQM31Var,
        claim: &BlakeContextClaimVar,
    ) {
        columns_hasher.update(&claim.blake_round.m31, &self.round);
        columns_hasher.update(&claim.blake_g.m31, &self.g);
        columns_hasher.update_fixed_log_size(
            cairo_air::components::blake_round_sigma::LOG_SIZE,
            &self.sigma,
        );
        columns_hasher.update(&claim.triple_xor_32.m31, &self.triple_xor_32);
        columns_hasher.update_fixed_log_size(
            cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
            &self.verify_bitwise_xor_12,
        );
    }
}

pub struct RangeChecksInteractionQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: [QM31Var; 1],
    pub range_check_8: [QM31Var; 1],
    pub range_check_11: [QM31Var; 1],
    pub range_check_12: [QM31Var; 1],
    pub range_check_18: [QM31Var; 1],
    pub range_check_18_b: [QM31Var; 1],
    pub range_check_20: [QM31Var; 1],
    pub range_check_20_b: [QM31Var; 1],
    pub range_check_20_c: [QM31Var; 1],
    pub range_check_20_d: [QM31Var; 1],
    pub range_check_20_e: [QM31Var; 1],
    pub range_check_20_f: [QM31Var; 1],
    pub range_check_20_g: [QM31Var; 1],
    pub range_check_20_h: [QM31Var; 1],
    pub range_check_4_3: [QM31Var; 1],
    pub range_check_4_4: [QM31Var; 1],
    pub range_check_5_4: [QM31Var; 1],
    pub range_check_9_9: [QM31Var; 1],
    pub range_check_9_9_b: [QM31Var; 1],
    pub range_check_9_9_c: [QM31Var; 1],
    pub range_check_9_9_d: [QM31Var; 1],
    pub range_check_9_9_e: [QM31Var; 1],
    pub range_check_9_9_f: [QM31Var; 1],
    pub range_check_9_9_g: [QM31Var; 1],
    pub range_check_9_9_h: [QM31Var; 1],
    pub range_check_7_2_5: [QM31Var; 1],
    pub range_check_3_6_6_3: [QM31Var; 1],
    pub range_check_4_4_4_4: [QM31Var; 1],
    pub range_check_3_3_3_3_3: [QM31Var; 1],
}

impl Var for RangeChecksInteractionQueryResultVar {
    type Value = RangeChecksInteractionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for RangeChecksInteractionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            range_check_6: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_6[i], mode)
            }),
            range_check_8: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_8[i], mode)
            }),
            range_check_11: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_11[i], mode)
            }),
            range_check_12: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_12[i], mode)
            }),
            range_check_18: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_18[i], mode)
            }),
            range_check_18_b: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_18_b[i], mode)
            }),
            range_check_20: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20[i], mode)
            }),
            range_check_20_b: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_b[i], mode)
            }),
            range_check_20_c: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_c[i], mode)
            }),
            range_check_20_d: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_d[i], mode)
            }),
            range_check_20_e: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_e[i], mode)
            }),
            range_check_20_f: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_f[i], mode)
            }),
            range_check_20_g: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_g[i], mode)
            }),
            range_check_20_h: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_20_h[i], mode)
            }),
            range_check_4_3: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_4_3[i], mode)
            }),
            range_check_4_4: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_4_4[i], mode)
            }),
            range_check_5_4: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_5_4[i], mode)
            }),
            range_check_9_9: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9[i], mode)
            }),
            range_check_9_9_b: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_b[i], mode)
            }),
            range_check_9_9_c: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_c[i], mode)
            }),
            range_check_9_9_d: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_d[i], mode)
            }),
            range_check_9_9_e: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_e[i], mode)
            }),
            range_check_9_9_f: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_f[i], mode)
            }),
            range_check_9_9_g: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_g[i], mode)
            }),
            range_check_9_9_h: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_9_9_h[i], mode)
            }),
            range_check_7_2_5: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_7_2_5[i], mode)
            }),
            range_check_3_6_6_3: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_3_6_6_3[i], mode)
            }),
            range_check_4_4_4_4: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_4_4_4_4[i], mode)
            }),
            range_check_3_3_3_3_3: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.range_check_3_3_3_3_3[i], mode)
            }),
        }
    }
}

impl RangeChecksInteractionQueryResultVar {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherQM31Var) {
        columns_hasher
            .update_fixed_log_size(components::range_check_6::LOG_SIZE, &self.range_check_6);
        columns_hasher
            .update_fixed_log_size(components::range_check_8::LOG_SIZE, &self.range_check_8);
        columns_hasher
            .update_fixed_log_size(components::range_check_11::LOG_SIZE, &self.range_check_11);
        columns_hasher
            .update_fixed_log_size(components::range_check_12::LOG_SIZE, &self.range_check_12);
        columns_hasher
            .update_fixed_log_size(components::range_check_18::LOG_SIZE, &self.range_check_18);
        columns_hasher.update_fixed_log_size(
            components::range_check_18_b::LOG_SIZE,
            &self.range_check_18_b,
        );
        columns_hasher
            .update_fixed_log_size(components::range_check_20::LOG_SIZE, &self.range_check_20);
        columns_hasher.update_fixed_log_size(
            components::range_check_20_b::LOG_SIZE,
            &self.range_check_20_b,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_20_c::LOG_SIZE,
            &self.range_check_20_c,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_20_d::LOG_SIZE,
            &self.range_check_20_d,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_20_e::LOG_SIZE,
            &self.range_check_20_e,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_20_f::LOG_SIZE,
            &self.range_check_20_f,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_20_g::LOG_SIZE,
            &self.range_check_20_g,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_20_h::LOG_SIZE,
            &self.range_check_20_h,
        );
        columns_hasher
            .update_fixed_log_size(components::range_check_4_3::LOG_SIZE, &self.range_check_4_3);
        columns_hasher
            .update_fixed_log_size(components::range_check_4_4::LOG_SIZE, &self.range_check_4_4);
        columns_hasher
            .update_fixed_log_size(components::range_check_5_4::LOG_SIZE, &self.range_check_5_4);
        columns_hasher
            .update_fixed_log_size(components::range_check_9_9::LOG_SIZE, &self.range_check_9_9);
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_b::LOG_SIZE,
            &self.range_check_9_9_b,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_c::LOG_SIZE,
            &self.range_check_9_9_c,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_d::LOG_SIZE,
            &self.range_check_9_9_d,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_e::LOG_SIZE,
            &self.range_check_9_9_e,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_f::LOG_SIZE,
            &self.range_check_9_9_f,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_g::LOG_SIZE,
            &self.range_check_9_9_g,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_9_9_h::LOG_SIZE,
            &self.range_check_9_9_h,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_7_2_5::LOG_SIZE,
            &self.range_check_7_2_5,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_3_6_6_3::LOG_SIZE,
            &self.range_check_3_6_6_3,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_4_4_4_4::LOG_SIZE,
            &self.range_check_4_4_4_4,
        );
        columns_hasher.update_fixed_log_size(
            components::range_check_3_3_3_3_3::LOG_SIZE,
            &self.range_check_3_3_3_3_3,
        );
    }
}

pub struct VerifyBitwiseInteractionQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: [QM31Var; 1],
    pub verify_bitwise_xor_7: [QM31Var; 1],
    pub verify_bitwise_xor_8: [QM31Var; 1],
    pub verify_bitwise_xor_8_b: [QM31Var; 1],
    pub verify_bitwise_xor_9: [QM31Var; 1],
}

impl Var for VerifyBitwiseInteractionQueryResultVar {
    type Value = VerifyBitwiseInteractionQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for VerifyBitwiseInteractionQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            verify_bitwise_xor_4: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_bitwise_xor_4[i], mode)
            }),
            verify_bitwise_xor_7: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_bitwise_xor_7[i], mode)
            }),
            verify_bitwise_xor_8: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_bitwise_xor_8[i], mode)
            }),
            verify_bitwise_xor_8_b: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_bitwise_xor_8_b[i], mode)
            }),
            verify_bitwise_xor_9: std::array::from_fn(|i| {
                QM31Var::new_variables(cs, &value.verify_bitwise_xor_9[i], mode)
            }),
        }
    }
}

impl VerifyBitwiseInteractionQueryResultVar {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherQM31Var) {
        columns_hasher.update_fixed_log_size(
            components::verify_bitwise_xor_4::LOG_SIZE,
            &self.verify_bitwise_xor_4,
        );
        columns_hasher.update_fixed_log_size(
            components::verify_bitwise_xor_7::LOG_SIZE,
            &self.verify_bitwise_xor_7,
        );
        columns_hasher.update_fixed_log_size(
            components::verify_bitwise_xor_8::LOG_SIZE,
            &self.verify_bitwise_xor_8,
        );
        columns_hasher.update_fixed_log_size(
            components::verify_bitwise_xor_8_b::LOG_SIZE,
            &self.verify_bitwise_xor_8_b,
        );
        columns_hasher.update_fixed_log_size(
            components::verify_bitwise_xor_9::LOG_SIZE,
            &self.verify_bitwise_xor_9,
        );
    }
}
