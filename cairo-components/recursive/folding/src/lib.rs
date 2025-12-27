use cairo_plonk_dsl_data_structures::CairoProofVar;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
use cairo_plonk_dsl_hints::folding::{CairoFoldingHints, SinglePairMerkleProof};
use circle_plonk_dsl_constraint_system::{
    var::{AllocVar, AllocationMode, Var},
    ConstraintSystemRef,
};
use circle_plonk_dsl_primitives::{
    option::OptionVar, BitVar, BitsVar, HashVar, Poseidon2HalfVar, Poseidon31MerkleHasherVar,
    QM31Var,
};
use indexmap::IndexMap;
use num_traits::Zero;
use stwo::core::fields::qm31::QM31;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::MAX_SEQUENCE_LOG_SIZE;

pub struct PaddedSinglePairMerkleProofVar {
    pub cs: ConstraintSystemRef,
    pub value: SinglePairMerkleProof,
    pub sibling_hashes: Vec<HashVar>,
    pub columns: IndexMap<usize, OptionVar<(QM31Var, QM31Var)>>,
}

impl Var for PaddedSinglePairMerkleProofVar {
    type Value = SinglePairMerkleProof;

    fn cs(&self) -> ConstraintSystemRef {
        self.cs.clone()
    }
}

impl AllocVar for PaddedSinglePairMerkleProofVar {
    fn new_variables(
        cs: &ConstraintSystemRef,
        value: &SinglePairMerkleProof,
        mode: AllocationMode,
    ) -> Self {
        let log_blowup_factor = value.log_blowup_factor;

        let mut sibling_hashes = vec![];
        for sibling_hash in value.sibling_hashes.iter() {
            sibling_hashes.push(HashVar::new_variables(cs, sibling_hash, mode));
        }

        let mut columns = IndexMap::new();

        // Pad columns for indices from LOG_N_LANES + 1..=MAX_SEQUENCE_LOG_SIZE + 1
        for index in (((LOG_N_LANES + log_blowup_factor) as usize)
            ..=((MAX_SEQUENCE_LOG_SIZE + log_blowup_factor) as usize))
            .rev()
        {
            let self_present = value.self_columns.contains_key(&index);
            let sibling_present = value.siblings_columns.contains_key(&index);

            // Assert that self_columns and siblings_columns are present or absent together
            assert_eq!(
                self_present, sibling_present,
                "self_columns and siblings_columns must be present or absent together at index {}",
                index
            );

            if self_present {
                // Both are present, allocate as OptionVar with is_some = true
                let self_qm31 = value.self_columns.get(&index).unwrap();
                let sibling_qm31 = value.siblings_columns.get(&index).unwrap();
                let self_var = QM31Var::new_variables(cs, self_qm31, mode);
                let sibling_var = QM31Var::new_variables(cs, sibling_qm31, mode);
                let is_some = BitVar::new_variables(cs, &true, mode);
                columns.insert(index, OptionVar::new(is_some, (self_var, sibling_var)));
            } else {
                // Both are not present, allocate as OptionVar with ZERO and is_some = false
                let self_var = QM31Var::new_variables(cs, &QM31::zero(), mode);
                let sibling_var = QM31Var::new_variables(cs, &QM31::zero(), mode);
                let is_some = BitVar::new_variables(cs, &false, mode);
                columns.insert(index, OptionVar::new(is_some, (self_var, sibling_var)));
            }
        }

        Self {
            cs: cs.clone(),
            value: value.clone(),
            sibling_hashes,
            columns,
        }
    }
}

impl PaddedSinglePairMerkleProofVar {
    pub fn verify(&mut self, root: &HashVar, query: &BitsVar) {
        // verify that the Merkle proof is valid
        self.value.verify();
        assert_eq!(root.value(), self.value.root.0);
        assert_eq!(query.get_value().0, self.value.query as u32);

        // TODO: Remove dependency on self.value.depth - the code should work for any depth
        // Currently assumes depth is in the padded range. Need to handle cases where depth
        // is outside the padded range or make depth dynamic.
        // Get the column pair at depth
        let depth_column = self.columns.get(&self.value.depth).unwrap();

        // assumption: the depth level must have values
        let mut self_hash =
            Poseidon31MerkleHasherVar::hash_qm31_columns_get_rate(&[depth_column.value.0.clone()]);
        let mut sibling_hash =
            Poseidon31MerkleHasherVar::hash_qm31_columns_get_rate(&[depth_column.value.1.clone()]);

        println!("self.columns keys: {:?}", self.columns.keys());

        // TODO: Remove dependency on self.value.depth - the loop should work for any depth
        // Currently the loop range is fixed to self.value.depth, but should be dynamic
        // based on the actual tree structure.
        for i in 0..self.value.depth {
            let h = self.value.depth - i - 1;
            println!("h: {:?}", h);

            self_hash = if let Some(column_opt) = self.columns.get(&h) {
                let (self_col, _, is_column_present) = (
                    &column_opt.value.0,
                    &column_opt.value.1,
                    &column_opt.is_some,
                );
                // Hash the columns to get column hash
                let self_column_hash =
                    Poseidon31MerkleHasherVar::hash_qm31_columns_get_capacity(&[self_col.clone()]);

                // Hash tree with swap
                let tree_hash = Poseidon31MerkleHasherVar::hash_tree_with_swap(
                    &self_hash,
                    &sibling_hash,
                    &query.0[i],
                )
                .to_qm31();

                // If column is present (is_some = true), combine with column hash
                // Otherwise, just use the tree hash
                let case_without_column = tree_hash.clone();
                let case_with_column = Poseidon2HalfVar::permute_get_rate(
                    &Poseidon2HalfVar::from_qm31(&tree_hash[0], &tree_hash[1]),
                    &self_column_hash,
                )
                .to_qm31();

                // Select based on is_column_present
                let final_self_hash = [
                    QM31Var::select(
                        &case_without_column[0],
                        &case_with_column[0],
                        is_column_present,
                    ),
                    QM31Var::select(
                        &case_without_column[1],
                        &case_with_column[1],
                        is_column_present,
                    ),
                ];
                Poseidon2HalfVar::from_qm31(&final_self_hash[0], &final_self_hash[1])
            } else {
                Poseidon31MerkleHasherVar::hash_tree_with_swap(
                    &self_hash,
                    &sibling_hash,
                    &query.0[i],
                )
            };

            if i != self.value.depth - 1 {
                sibling_hash = if let Some(column_opt) = self.columns.get(&h) {
                    let (_, sibling_col, is_column_present) = (
                        &column_opt.value.0,
                        &column_opt.value.1,
                        &column_opt.is_some,
                    );
                    let sibling_column_hash =
                        Poseidon31MerkleHasherVar::hash_qm31_columns_get_capacity(&[
                            sibling_col.clone()
                        ]);

                    // Handle sibling hash - always combine with column hash if present
                    let sibling_tree_hash = self.sibling_hashes[i].clone();
                    let sibling_with_column =
                        Poseidon31MerkleHasherVar::combine_hash_tree_with_column(
                            &sibling_tree_hash,
                            &sibling_column_hash,
                        );
                    let sibling_without_column = sibling_tree_hash;

                    // Select sibling hash based on is_column_present
                    let final_sibling_hash = [
                        QM31Var::select(
                            &sibling_without_column.to_qm31()[0],
                            &sibling_with_column.to_qm31()[0],
                            is_column_present,
                        ),
                        QM31Var::select(
                            &sibling_without_column.to_qm31()[1],
                            &sibling_with_column.to_qm31()[1],
                            is_column_present,
                        ),
                    ];

                    Poseidon2HalfVar::from_qm31(&final_sibling_hash[0], &final_sibling_hash[1])
                } else {
                    self.sibling_hashes[i].clone()
                };
            }
        }

        assert_eq!(self_hash.value(), root.value());

        // check that the left_variable and right_variable are the same
        // as though in self.root
        self_hash.equalverify(root);
    }
}

pub struct FoldingResults {}

impl FoldingResults {
    pub fn new(
        folding_hints: &CairoFoldingHints,
        fiat_shamir_results: &CairoFiatShamirResults,
        proof_var: &CairoProofVar,
    ) -> Self {
        let cs = fiat_shamir_results.max_log_size.cs();

        for (i, proof) in folding_hints
            .first_layer_hints
            .merkle_proofs
            .iter()
            .enumerate()
        {
            let mut proof = PaddedSinglePairMerkleProofVar::new_witness(&cs, proof);
            proof.verify(
                &proof_var.stark_proof.fri_proof.first_layer.commitment,
                &fiat_shamir_results.queries[i],
            );
        }

        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_hints::{AnswerHints, CairoFiatShamirHints};
    use circle_plonk_dsl_constraint_system::ConstraintSystemRef;
    use std::path::PathBuf;

    #[test]
    fn test_folding_results() {
        let cs = ConstraintSystemRef::new();

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let data_path = PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_data")
            .join("recursive_proof.bin.bz");

        let proof = deserialize_proof_from_file(&data_path, ProofFormat::Binary).unwrap();

        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        let answer_hints = AnswerHints::new(&fiat_shamir_hints, &proof);

        let folding_hints = CairoFoldingHints::new(&fiat_shamir_hints, &answer_hints, &proof);
        let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);
        let _ = FoldingResults::new(&folding_hints, &fiat_shamir_results, &proof_var);
    }
}
