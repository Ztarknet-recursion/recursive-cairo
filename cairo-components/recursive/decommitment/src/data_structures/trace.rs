use cairo_air::components;
use cairo_plonk_dsl_data_structures::{BlakeContextClaimVar, CairoClaimVar, OpcodeClaimVar};
use cairo_plonk_dsl_hints::decommitment::{
    BlakeTraceQueryResult, OpcodesTraceQueryResult, RangeChecksTraceQueryResult, TraceQueryResult,
    VerifyBitwiseTraceQueryResult,
};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{option::OptionVar, M31Var, Poseidon2HalfVar};
use indexmap::IndexMap;

use crate::utils::ColumnsHasherVar;

pub struct TraceQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub opcodes: OpcodesTraceQueryResultVar,
    pub verify_instruction: [M31Var; components::verify_instruction::N_TRACE_COLUMNS],
    pub blake: BlakeTraceQueryResultVar,
    pub range_check_128_builtin:
        [M31Var; components::range_check_builtin_bits_128::N_TRACE_COLUMNS],
    pub memory_address_to_id: [M31Var; components::memory_address_to_id::N_TRACE_COLUMNS],
    pub memory_id_to_big_big: [M31Var; components::memory_id_to_big::BIG_N_COLUMNS],
    pub memory_id_to_big_small: [M31Var; components::memory_id_to_big::SMALL_N_COLUMNS],
    pub range_checks: RangeChecksTraceQueryResultVar,
    pub verify_bitwise: VerifyBitwiseTraceQueryResultVar,
}

impl Var for TraceQueryResultVar {
    type Value = TraceQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for TraceQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            opcodes: AllocVar::new_variables(cs, &value.opcodes, mode),
            verify_instruction: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_instruction[i], mode)
            }),
            blake: AllocVar::new_variables(cs, &value.blake, mode),
            range_check_128_builtin: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_128_builtin[i], mode)
            }),
            memory_address_to_id: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.memory_address_to_id[i], mode)
            }),
            memory_id_to_big_big: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.memory_id_to_big_big[i], mode)
            }),
            memory_id_to_big_small: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.memory_id_to_big_small[i], mode)
            }),
            range_checks: AllocVar::new_variables(cs, &value.range_checks, mode),
            verify_bitwise: AllocVar::new_variables(cs, &value.verify_bitwise, mode),
        }
    }
}

impl TraceQueryResultVar {
    pub fn compute_column_hashes(
        &self,
        claim: &CairoClaimVar,
    ) -> IndexMap<usize, OptionVar<Poseidon2HalfVar>> {
        let mut columns_hasher = ColumnsHasherVar::new(&self.cs);
        self.opcodes
            .update_hashes(&mut columns_hasher, &claim.opcode_claim);
        columns_hasher.update(&claim.verify_instruction, &self.verify_instruction);
        self.blake
            .update_hashes(&mut columns_hasher, &claim.blake_context);
        columns_hasher.update(
            &claim.builtins.range_check_128_builtin_log_size,
            &self.range_check_128_builtin,
        );
        columns_hasher.update(&claim.memory_address_to_id, &self.memory_address_to_id);
        columns_hasher.update(
            &claim.memory_id_to_value.big_log_size,
            &self.memory_id_to_big_big,
        );
        columns_hasher.update(
            &claim.memory_id_to_value.small_log_size,
            &self.memory_id_to_big_small,
        );
        self.range_checks.update_hashes(&mut columns_hasher);
        self.verify_bitwise.update_hashes(&mut columns_hasher);
        columns_hasher.finalize()
    }
}

pub struct OpcodesTraceQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub add: [M31Var; components::add_opcode::N_TRACE_COLUMNS],
    pub add_small: [M31Var; components::add_opcode_small::N_TRACE_COLUMNS],
    pub add_ap: [M31Var; components::add_ap_opcode::N_TRACE_COLUMNS],
    pub assert_eq: [M31Var; components::assert_eq_opcode::N_TRACE_COLUMNS],
    pub assert_eq_imm: [M31Var; components::assert_eq_opcode_imm::N_TRACE_COLUMNS],
    pub assert_eq_double_deref:
        [M31Var; components::assert_eq_opcode_double_deref::N_TRACE_COLUMNS],
    pub blake: [M31Var; components::blake_compress_opcode::N_TRACE_COLUMNS],
    pub call: [M31Var; components::call_opcode_abs::N_TRACE_COLUMNS],
    pub call_rel_imm: [M31Var; components::call_opcode_rel_imm::N_TRACE_COLUMNS],
    pub jnz: [M31Var; components::jnz_opcode_non_taken::N_TRACE_COLUMNS],
    pub jnz_taken: [M31Var; components::jnz_opcode_taken::N_TRACE_COLUMNS],
    pub jump_rel: [M31Var; components::jump_opcode_rel::N_TRACE_COLUMNS],
    pub jump_rel_imm: [M31Var; components::jump_opcode_rel_imm::N_TRACE_COLUMNS],
    pub mul: [M31Var; components::mul_opcode::N_TRACE_COLUMNS],
    pub mul_small: [M31Var; components::mul_opcode_small::N_TRACE_COLUMNS],
    pub qm31: [M31Var; components::qm_31_add_mul_opcode::N_TRACE_COLUMNS],
    pub ret: [M31Var; components::ret_opcode::N_TRACE_COLUMNS],
}

impl Var for OpcodesTraceQueryResultVar {
    type Value = OpcodesTraceQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for OpcodesTraceQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            add: std::array::from_fn(|i| M31Var::new_variables(cs, &value.add[i], mode)),
            add_small: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.add_small[i], mode)
            }),
            add_ap: std::array::from_fn(|i| M31Var::new_variables(cs, &value.add_ap[i], mode)),
            assert_eq: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.assert_eq[i], mode)
            }),
            assert_eq_imm: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.assert_eq_imm[i], mode)
            }),
            assert_eq_double_deref: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.assert_eq_double_deref[i], mode)
            }),
            blake: std::array::from_fn(|i| M31Var::new_variables(cs, &value.blake[i], mode)),
            call: std::array::from_fn(|i| M31Var::new_variables(cs, &value.call[i], mode)),
            call_rel_imm: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.call_rel_imm[i], mode)
            }),
            jnz: std::array::from_fn(|i| M31Var::new_variables(cs, &value.jnz[i], mode)),
            jnz_taken: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.jnz_taken[i], mode)
            }),
            jump_rel: std::array::from_fn(|i| M31Var::new_variables(cs, &value.jump_rel[i], mode)),
            jump_rel_imm: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.jump_rel_imm[i], mode)
            }),
            mul: std::array::from_fn(|i| M31Var::new_variables(cs, &value.mul[i], mode)),
            mul_small: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.mul_small[i], mode)
            }),
            qm31: std::array::from_fn(|i| M31Var::new_variables(cs, &value.qm31[i], mode)),
            ret: std::array::from_fn(|i| M31Var::new_variables(cs, &value.ret[i], mode)),
        }
    }
}

impl OpcodesTraceQueryResultVar {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherVar, claim: &OpcodeClaimVar) {
        columns_hasher.update(&claim.add, &self.add);
        columns_hasher.update(&claim.add_small, &self.add_small);
        columns_hasher.update(&claim.add_ap, &self.add_ap);
        columns_hasher.update(&claim.assert_eq, &self.assert_eq);
        columns_hasher.update(&claim.assert_eq_imm, &self.assert_eq_imm);
        columns_hasher.update(&claim.assert_eq_double_deref, &self.assert_eq_double_deref);
        columns_hasher.update(&claim.blake, &self.blake);
        columns_hasher.update(&claim.call, &self.call);
        columns_hasher.update(&claim.call_rel_imm, &self.call_rel_imm);
        columns_hasher.update(&claim.jnz, &self.jnz);
        columns_hasher.update(&claim.jnz_taken, &self.jnz_taken);
        columns_hasher.update(&claim.jump_rel, &self.jump_rel);
        columns_hasher.update(&claim.jump_rel_imm, &self.jump_rel_imm);
        columns_hasher.update(&claim.mul, &self.mul);
        columns_hasher.update(&claim.mul_small, &self.mul_small);
        columns_hasher.update(&claim.qm31, &self.qm31);
        columns_hasher.update(&claim.ret, &self.ret);
    }
}

pub struct BlakeTraceQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub round: [M31Var; components::blake_round::N_TRACE_COLUMNS],
    pub g: [M31Var; components::blake_g::N_TRACE_COLUMNS],
    pub sigma: [M31Var; components::blake_round_sigma::N_TRACE_COLUMNS],
    pub triple_xor_32: [M31Var; components::triple_xor_32::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_12: [M31Var; components::verify_bitwise_xor_12::N_TRACE_COLUMNS],
}

impl Var for BlakeTraceQueryResultVar {
    type Value = BlakeTraceQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for BlakeTraceQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            round: std::array::from_fn(|i| M31Var::new_variables(cs, &value.round[i], mode)),
            g: std::array::from_fn(|i| M31Var::new_variables(cs, &value.g[i], mode)),
            sigma: std::array::from_fn(|i| M31Var::new_variables(cs, &value.sigma[i], mode)),
            triple_xor_32: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.triple_xor_32[i], mode)
            }),
            verify_bitwise_xor_12: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_bitwise_xor_12[i], mode)
            }),
        }
    }
}

impl BlakeTraceQueryResultVar {
    pub fn update_hashes(
        &self,
        columns_hasher: &mut ColumnsHasherVar,
        claim: &BlakeContextClaimVar,
    ) {
        columns_hasher.update(&claim.blake_round, &self.round);
        columns_hasher.update(&claim.blake_g, &self.g);
        columns_hasher.update_fixed_log_size(
            cairo_air::components::blake_round_sigma::LOG_SIZE,
            &self.sigma,
        );
        columns_hasher.update(&claim.triple_xor_32, &self.triple_xor_32);
        columns_hasher.update_fixed_log_size(
            cairo_air::components::verify_bitwise_xor_12::LOG_SIZE,
            &self.verify_bitwise_xor_12,
        );
    }
}

pub struct RangeChecksTraceQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub range_check_6: [M31Var; components::range_check_6::N_TRACE_COLUMNS],
    pub range_check_8: [M31Var; components::range_check_8::N_TRACE_COLUMNS],
    pub range_check_11: [M31Var; components::range_check_11::N_TRACE_COLUMNS],
    pub range_check_12: [M31Var; components::range_check_12::N_TRACE_COLUMNS],
    pub range_check_18: [M31Var; components::range_check_18::N_TRACE_COLUMNS],
    pub range_check_18_b: [M31Var; components::range_check_18_b::N_TRACE_COLUMNS],
    pub range_check_20: [M31Var; components::range_check_20::N_TRACE_COLUMNS],
    pub range_check_20_b: [M31Var; components::range_check_20_b::N_TRACE_COLUMNS],
    pub range_check_20_c: [M31Var; components::range_check_20_c::N_TRACE_COLUMNS],
    pub range_check_20_d: [M31Var; components::range_check_20_d::N_TRACE_COLUMNS],
    pub range_check_20_e: [M31Var; components::range_check_20_e::N_TRACE_COLUMNS],
    pub range_check_20_f: [M31Var; components::range_check_20_f::N_TRACE_COLUMNS],
    pub range_check_20_g: [M31Var; components::range_check_20_g::N_TRACE_COLUMNS],
    pub range_check_20_h: [M31Var; components::range_check_20_h::N_TRACE_COLUMNS],
    pub range_check_4_3: [M31Var; components::range_check_4_3::N_TRACE_COLUMNS],
    pub range_check_4_4: [M31Var; components::range_check_4_4::N_TRACE_COLUMNS],
    pub range_check_5_4: [M31Var; components::range_check_5_4::N_TRACE_COLUMNS],
    pub range_check_9_9: [M31Var; components::range_check_9_9::N_TRACE_COLUMNS],
    pub range_check_9_9_b: [M31Var; components::range_check_9_9_b::N_TRACE_COLUMNS],
    pub range_check_9_9_c: [M31Var; components::range_check_9_9_c::N_TRACE_COLUMNS],
    pub range_check_9_9_d: [M31Var; components::range_check_9_9_d::N_TRACE_COLUMNS],
    pub range_check_9_9_e: [M31Var; components::range_check_9_9_e::N_TRACE_COLUMNS],
    pub range_check_9_9_f: [M31Var; components::range_check_9_9_f::N_TRACE_COLUMNS],
    pub range_check_9_9_g: [M31Var; components::range_check_9_9_g::N_TRACE_COLUMNS],
    pub range_check_9_9_h: [M31Var; components::range_check_9_9_h::N_TRACE_COLUMNS],
    pub range_check_7_2_5: [M31Var; components::range_check_7_2_5::N_TRACE_COLUMNS],
    pub range_check_3_6_6_3: [M31Var; components::range_check_3_6_6_3::N_TRACE_COLUMNS],
    pub range_check_4_4_4_4: [M31Var; components::range_check_4_4_4_4::N_TRACE_COLUMNS],
    pub range_check_3_3_3_3_3: [M31Var; components::range_check_3_3_3_3_3::N_TRACE_COLUMNS],
}

impl Var for RangeChecksTraceQueryResultVar {
    type Value = RangeChecksTraceQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for RangeChecksTraceQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            range_check_6: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_6[i], mode)
            }),
            range_check_8: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_8[i], mode)
            }),
            range_check_11: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_11[i], mode)
            }),
            range_check_12: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_12[i], mode)
            }),
            range_check_18: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_18[i], mode)
            }),
            range_check_18_b: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_18_b[i], mode)
            }),
            range_check_20: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20[i], mode)
            }),
            range_check_20_b: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_b[i], mode)
            }),
            range_check_20_c: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_c[i], mode)
            }),
            range_check_20_d: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_d[i], mode)
            }),
            range_check_20_e: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_e[i], mode)
            }),
            range_check_20_f: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_f[i], mode)
            }),
            range_check_20_g: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_g[i], mode)
            }),
            range_check_20_h: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_20_h[i], mode)
            }),
            range_check_4_3: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_4_3[i], mode)
            }),
            range_check_4_4: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_4_4[i], mode)
            }),
            range_check_5_4: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_5_4[i], mode)
            }),
            range_check_9_9: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9[i], mode)
            }),
            range_check_9_9_b: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_b[i], mode)
            }),
            range_check_9_9_c: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_c[i], mode)
            }),
            range_check_9_9_d: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_d[i], mode)
            }),
            range_check_9_9_e: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_e[i], mode)
            }),
            range_check_9_9_f: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_f[i], mode)
            }),
            range_check_9_9_g: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_g[i], mode)
            }),
            range_check_9_9_h: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_9_9_h[i], mode)
            }),
            range_check_7_2_5: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_7_2_5[i], mode)
            }),
            range_check_3_6_6_3: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_3_6_6_3[i], mode)
            }),
            range_check_4_4_4_4: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_4_4_4_4[i], mode)
            }),
            range_check_3_3_3_3_3: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.range_check_3_3_3_3_3[i], mode)
            }),
        }
    }
}

impl RangeChecksTraceQueryResultVar {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherVar) {
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

pub struct VerifyBitwiseTraceQueryResultVar {
    pub cs: ConstraintSystemRef,
    pub verify_bitwise_xor_4: [M31Var; components::verify_bitwise_xor_4::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_7: [M31Var; components::verify_bitwise_xor_7::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8: [M31Var; components::verify_bitwise_xor_8::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_8_b: [M31Var; components::verify_bitwise_xor_8_b::N_TRACE_COLUMNS],
    pub verify_bitwise_xor_9: [M31Var; components::verify_bitwise_xor_9::N_TRACE_COLUMNS],
}

impl Var for VerifyBitwiseTraceQueryResultVar {
    type Value = VerifyBitwiseTraceQueryResult;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for VerifyBitwiseTraceQueryResultVar {
    fn new_variables(cs: &ConstraintSystemRef, value: &Self::Value, mode: AllocationMode) -> Self {
        Self {
            cs: cs.clone(),
            verify_bitwise_xor_4: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_bitwise_xor_4[i], mode)
            }),
            verify_bitwise_xor_7: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_bitwise_xor_7[i], mode)
            }),
            verify_bitwise_xor_8: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_bitwise_xor_8[i], mode)
            }),
            verify_bitwise_xor_8_b: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_bitwise_xor_8_b[i], mode)
            }),
            verify_bitwise_xor_9: std::array::from_fn(|i| {
                M31Var::new_variables(cs, &value.verify_bitwise_xor_9[i], mode)
            }),
        }
    }
}

impl VerifyBitwiseTraceQueryResultVar {
    pub fn update_hashes(&self, columns_hasher: &mut ColumnsHasherVar) {
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
