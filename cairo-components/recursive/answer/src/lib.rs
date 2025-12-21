pub mod data_structures;
use cairo_plonk_dsl_data_structures::stark_proof::StarkProofVar;
pub use data_structures::*;

pub struct AnswerResults {}

impl AnswerResults {
    pub fn compute(stark_proof: &StarkProofVar) -> AnswerResults {
        let _ = PreprocessedTraceSampleResultVar::new(
            &stark_proof.sampled_values[0],
            &stark_proof.is_preprocessed_trace_present,
        );
        Self {}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_data_structures::CairoProofVar;
    use circle_plonk_dsl_constraint_system::{var::AllocVar, ConstraintSystemRef};
    use std::path::PathBuf;

    #[test]
    fn test_answer_results() {
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
        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        let _ = AnswerResults::compute(&proof_var.stark_proof);
    }
}
