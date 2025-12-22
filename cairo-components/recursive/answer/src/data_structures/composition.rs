use circle_plonk_dsl_primitives::QM31Var;
use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;


pub struct CompositionSampleResultVar(pub [[QM31Var; SECURE_EXTENSION_DEGREE]; 2]);

impl CompositionSampleResultVar {
    pub fn new(sampled_values: &Vec<Vec<QM31Var>>) -> Self {
        assert_eq!(sampled_values.len(), 8);
        Self([
            [sampled_values[0][0].clone(), sampled_values[1][0].clone(), sampled_values[2][0].clone(), sampled_values[3][0].clone()],
            [sampled_values[4][0].clone(), sampled_values[5][0].clone(), sampled_values[6][0].clone(), sampled_values[7][0].clone()],
        ])
    }
}