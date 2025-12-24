use cairo_plonk_dsl_decommitment::CairoDecommitmentResultsVar;
use circle_plonk_dsl_constraint_system::var::{AllocVar, Var};
use circle_plonk_dsl_primitives::{
    CM31Var, CirclePointM31Var, CirclePointQM31Var, M31Var, QM31Var,
};
use indexmap::IndexMap;
use itertools::Itertools;
use stwo::core::fields::{m31::M31, qm31::SECURE_EXTENSION_DEGREE};
use stwo_cairo_common::{
    preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE,
    prover_types::simd::LOG_N_LANES,
};

use crate::{complex_conjugate_line_coeffs_var, AnswerAccumulator};

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

pub struct CompositionQuotientConstantsVar(pub [[[CM31Var; 2]; SECURE_EXTENSION_DEGREE]; 2]);

impl CompositionQuotientConstantsVar {
    pub fn new(oods_point: &CirclePointQM31Var, entry: &CompositionSampleResultVar) -> Self {
        Self(std::array::from_fn(|i| {
            std::array::from_fn(|j| complex_conjugate_line_coeffs_var(oods_point, &entry.0[i][j]))
        }))
    }
}

pub fn compute_composition_answers(
    num_queries: usize,
    answer_accumulator: &mut Vec<AnswerAccumulator>,
    oods_point_y: &CM31Var,
    domain_points: &IndexMap<u32, Vec<CirclePointM31Var>>,
    denominator_inverses_with_oods_point: &IndexMap<u32, Vec<CM31Var>>,
    query_result: &CairoDecommitmentResultsVar,
    quotient_constants: &CompositionQuotientConstantsVar,
    composition_log_size: &M31Var,
) {
    let cs = oods_point_y.cs();

    let mut bitmap = IndexMap::new();
    for i in (LOG_N_LANES + 1)..=(MAX_SEQUENCE_LOG_SIZE + 1) {
        bitmap.insert(
            i - 1,
            composition_log_size.is_eq(&M31Var::new_constant(&cs, &M31::from(i))),
        );
    }

    for idx in 0..num_queries {
        let answer_accumulator = &mut answer_accumulator[idx];
        let query_result = &query_result[idx].composition_query_result;

        let mut x = M31Var::zero(&cs);
        let mut y = M31Var::zero(&cs);
        let mut denominator_inverse = CM31Var::zero(&cs);

        for i in (LOG_N_LANES + 1)..=(MAX_SEQUENCE_LOG_SIZE + 1) {
            let bit = bitmap.get(&(i - 1)).unwrap();
            x = &x + &(&bit.0 * &domain_points.get(&i).unwrap()[idx].x);
            y = &y + &(&bit.0 * &domain_points.get(&i).unwrap()[idx].y);
            denominator_inverse = &denominator_inverse
                + &(&denominator_inverses_with_oods_point.get(&i).unwrap()[idx] * &bit.0);
        }

        let mut update = vec![];
        quotient_constants
            .0
            .iter()
            .zip_eq(query_result.0.iter())
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

        {
            let mut bits = vec![];
            for (k, _) in answer_accumulator.map.iter() {
                let bit = bitmap.get(&(*k as u32)).unwrap();
                bits.push(bit);
            }

            let mut entry_answer = QM31Var::zero(&cs);
            let mut entry_multiplier = QM31Var::zero(&cs);

            for ((_, (answer, multiplier)), bit) in answer_accumulator.map.iter().zip(bits.iter()) {
                entry_answer = &entry_answer + &(answer * &bit.0);
                entry_multiplier = &entry_multiplier + &(multiplier * &bit.0);
            }

            for result in update.iter() {
                entry_answer = &entry_answer + &(result * &entry_multiplier);
                entry_multiplier = &entry_multiplier * &answer_accumulator.random_coeff;
            }

            for ((_, v), bit) in answer_accumulator.map.iter_mut().zip(bits.iter()) {
                v.0 = QM31Var::select(&v.0, &entry_answer, bit);
                v.1 = QM31Var::select(&v.1, &entry_multiplier, bit);
            }
        }
    }
}
