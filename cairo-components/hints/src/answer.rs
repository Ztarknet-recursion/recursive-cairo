use cairo_air::CairoProof;
use itertools::Itertools;
use std::cmp::Reverse;
use stwo::core::{
    fields::qm31::SecureField,
    pcs::quotients::{fri_answers, PointSample},
    vcs::poseidon31_merkle::Poseidon31MerkleHasher,
    ColumnVec,
};

use crate::CairoFiatShamirHints;

pub struct AnswerHints {
    pub answers: ColumnVec<Vec<SecureField>>,
}

impl AnswerHints {
    pub fn new(
        fiat_shamir_hints: &CairoFiatShamirHints,
        proof: &CairoProof<Poseidon31MerkleHasher>,
    ) -> Self {
        let samples = fiat_shamir_hints
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

        let log_sizes = column_log_sizes[0]
            .iter()
            .sorted_by_key(|log_size| Reverse(*log_size))
            .dedup()
            .filter(|log_size| fiat_shamir_hints.query_positions_per_log_size.get(log_size) != None)
            .collect_vec();

        let first_query = fiat_shamir_hints.raw_queries[0];

        let answers = fri_answers(
            column_log_sizes.clone(),
            samples,
            fiat_shamir_hints.after_sampled_values_random_coeff,
            &fiat_shamir_hints.query_positions_per_log_size,
            proof.stark_proof.queried_values.clone(),
            n_columns_per_log_size,
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

        Self { answers }
    }
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
