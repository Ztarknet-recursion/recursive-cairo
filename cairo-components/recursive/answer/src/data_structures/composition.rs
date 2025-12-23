use circle_plonk_dsl_primitives::{CM31Var, CirclePointQM31Var, QM31Var};
use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;

use crate::complex_conjugate_line_coeffs_var;

pub struct CompositionSampleResultVar(pub [[QM31Var; SECURE_EXTENSION_DEGREE]; 2]);

impl CompositionSampleResultVar {
    pub fn new(sampled_values: &Vec<Vec<QM31Var>>) -> Self {
        assert_eq!(sampled_values.len(), 8);
        Self([
            [
                sampled_values[0][0].clone(),
                sampled_values[1][0].clone(),
                sampled_values[2][0].clone(),
                sampled_values[3][0].clone(),
            ],
            [
                sampled_values[4][0].clone(),
                sampled_values[5][0].clone(),
                sampled_values[6][0].clone(),
                sampled_values[7][0].clone(),
            ],
        ])
    }
}

pub struct CompositionQuotientConstantsEntryVar(pub [[[CM31Var; 3]; SECURE_EXTENSION_DEGREE]; 2]);

impl CompositionQuotientConstantsEntryVar {
    pub fn new(oods_point: &CirclePointQM31Var, entry: &CompositionSampleResultVar) -> Self {
        Self(std::array::from_fn(|i| {
            std::array::from_fn(|j| complex_conjugate_line_coeffs_var(oods_point, &entry.0[i][j]))
        }))
    }
}
