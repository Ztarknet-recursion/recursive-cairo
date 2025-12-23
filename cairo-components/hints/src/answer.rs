use cairo_air::CairoProof;
use itertools::{izip, multiunzip, Itertools};
use std::{cmp::Reverse, collections::BTreeMap};
use stwo::core::{
    fields::{m31::BaseField, qm31::SecureField},
    pcs::{
        quotients::{accumulate_row_quotients, quotient_constants, ColumnSampleBatch, PointSample},
        TreeVec,
    },
    poly::circle::CanonicCoset,
    utils::bit_reverse_index,
    vcs::poseidon31_merkle::Poseidon31MerkleHasher,
    verifier::VerificationError,
    ColumnVec,
};

use crate::CairoFiatShamirHints;

pub struct AnswerHints {}

impl AnswerHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) {
        let _samples = fiat_shamir_hints
            .sample_points
            .clone()
            .zip_cols(proof.stark_proof.sampled_values.clone())
            .map_cols(|(sample_points, sampled_values)| {
                std::iter::zip(sample_points, sampled_values)
                    .map(|(point, value)| PointSample { point, value })
                    .collect_vec()
            });

        let n_columns_per_log_size = fiat_shamir_hints
            .commitment_scheme_verifier
            .trees
            .as_ref()
            .map(|tree| &tree.n_columns_per_log_size);

        // keep only the preprocessed trace
        let column_log_sizes = fiat_shamir_hints
            .commitment_scheme_verifier
            .column_log_sizes();

        let samples = fiat_shamir_hints.sample_points[0]
            .iter()
            .zip(proof.stark_proof.sampled_values[0].iter())
            .map(|(sample_points, sampled_values)| {
                std::iter::zip(sample_points, sampled_values)
                    .map(|(point, value)| PointSample {
                        point: point.clone(),
                        value: value.clone(),
                    })
                    .collect_vec()
            })
            .collect_vec();

        for (i, (log_size, sample)) in column_log_sizes[0]
            .iter()
            .zip(proof.stark_proof.sampled_values[0].iter())
            .enumerate()
        {
            if sample.is_empty() {
                println!("log_size: {:?}, i: {}", log_size, i);
            }
        }

        let log_sizes = column_log_sizes[0]
            .iter()
            .sorted_by_key(|log_size| Reverse(*log_size))
            .dedup()
            .filter(|log_size| fiat_shamir_hints.query_positions_per_log_size.get(log_size) != None)
            .collect_vec();

        let first_query = fiat_shamir_hints.raw_queries[0];

        let answers = fri_answers(
            TreeVec::new(vec![column_log_sizes[0].clone()]),
            TreeVec::new(vec![samples]),
            fiat_shamir_hints.after_sampled_values_random_coeff,
            &fiat_shamir_hints.query_positions_per_log_size,
            TreeVec::new(vec![proof.stark_proof.queried_values[0].clone()]),
            TreeVec::new(vec![n_columns_per_log_size[0]]),
        )
        .unwrap();

        let max_query = fiat_shamir_hints
            .query_positions_per_log_size
            .keys()
            .max()
            .unwrap();

        for (log_size, answer) in log_sizes.iter().zip(answers.iter()) {
            let queries_for_log_size = fiat_shamir_hints
                .query_positions_per_log_size
                .get(&log_size)
                .unwrap();

            for (query_position, answer) in queries_for_log_size.iter().zip(answer.iter()) {
                if *query_position == first_query >> (*max_query - **log_size) {
                    println!(
                        "log_size = {}, query_position: {:?}, answer: {:?}",
                        **log_size, *query_position, answer
                    );
                }
            }
        }
    }
}

pub fn fri_answers(
    column_log_sizes: TreeVec<Vec<u32>>,
    samples: TreeVec<Vec<Vec<PointSample>>>,
    random_coeff: SecureField,
    query_positions_per_log_size: &BTreeMap<u32, Vec<usize>>,
    queried_values: TreeVec<Vec<BaseField>>,
    n_columns_per_log_size: TreeVec<&BTreeMap<u32, usize>>,
) -> Result<ColumnVec<Vec<SecureField>>, VerificationError> {
    let mut queried_values = queried_values.map(|values| values.into_iter());

    izip!(column_log_sizes.flatten(), samples.flatten().iter())
        .sorted_by_key(|(log_size, ..)| Reverse(*log_size))
        .chunk_by(|(log_size, ..)| *log_size)
        .into_iter()
        .filter_map(|(log_size, tuples)| {
            // Skip processing this log size if it does not have any associated queries.
            let queries_for_log_size = query_positions_per_log_size.get(&log_size)?;
            println!("log_size: {:?}", log_size);

            let (_, samples): (Vec<_>, Vec<_>) = multiunzip(tuples);
            Some(fri_answers_for_log_size(
                log_size,
                &samples,
                random_coeff,
                queries_for_log_size,
                &mut queried_values,
                n_columns_per_log_size
                    .as_ref()
                    .map(|columns_log_sizes| *columns_log_sizes.get(&log_size).unwrap_or(&0)),
            ))
        })
        .collect()
}

pub fn fri_answers_for_log_size(
    log_size: u32,
    samples: &[&Vec<PointSample>],
    random_coeff: SecureField,
    query_positions: &[usize],
    queried_values: &mut TreeVec<impl Iterator<Item = BaseField>>,
    n_columns: TreeVec<usize>,
) -> Result<Vec<SecureField>, VerificationError> {
    let sample_batches = ColumnSampleBatch::new_vec(samples);
    // TODO(ilya): Is it ok to use the same `random_coeff` for all log sizes.
    let quotient_constants = quotient_constants(&sample_batches, random_coeff);
    let commitment_domain = CanonicCoset::new(log_size).circle_domain();

    println!("query positions len: {:?}", query_positions.len());

    let mut quotient_evals_at_queries = Vec::new();
    for &query_position in query_positions {
        let domain_point = commitment_domain.at(bit_reverse_index(query_position, log_size));

        let queried_values_at_row = queried_values
            .as_mut()
            .zip_eq(n_columns.as_ref())
            .map(|(queried_values, n_columns)| queried_values.take(*n_columns).collect())
            .flatten();

        let res = accumulate_row_quotients(
            &sample_batches,
            &queried_values_at_row,
            &quotient_constants,
            domain_point,
        );

        quotient_evals_at_queries.push(res);
    }

    Ok(quotient_evals_at_queries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use std::path::PathBuf;

    #[test]
    fn test_answers_hints() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();
        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let _ = AnswerHints::new(&fiat_shamir_hints, &proof);
    }
}
