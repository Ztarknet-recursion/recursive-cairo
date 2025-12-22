pub mod data_structures;
use cairo_plonk_dsl_fiat_shamir::CairoFiatShamirResults;
pub use data_structures::*;

use cairo_plonk_dsl_data_structures::stark_proof::StarkProofVar;
use circle_plonk_dsl_constraint_system::var::Var;

pub struct AnswerResults {}

impl AnswerResults {
    pub fn compute(
        fiat_shamir_results: &CairoFiatShamirResults,
        stark_proof: &StarkProofVar
    ) -> AnswerResults {
        let cs = stark_proof.cs();

        let preprocessed_trace_sample_result = PreprocessedTraceSampleResultVar::new(
            &cs,
            &stark_proof.sampled_values[0],
            &stark_proof.is_preprocessed_trace_present,
        );
        let trace_sample_result = TraceSampleResultVar::new(&cs, &stark_proof.sampled_values[1]);
        let _ = InteractionSampleResultVar::new(&cs, &stark_proof.sampled_values[2]);
        let _ = CompositionSampleResultVar::new(&stark_proof.sampled_values[3]);

        for i in 0..stark_proof.is_preprocessed_trace_present.len() {
            if !stark_proof.is_preprocessed_trace_present[i].value() {
                println!("i: {}", i);
            }
        }

        let _preprocessed_trace_quotient_constants = PreprocessedTraceQuotientConstantsVar::new(
            &fiat_shamir_results.oods_point,
            &preprocessed_trace_sample_result,
        );
        let _trace_quotient_constants = TraceQuotientConstantsVar::new(
            &fiat_shamir_results.oods_point,
            &trace_sample_result,
        );

        let _answer_accumulator = AnswerAccumulator::new(&cs, &fiat_shamir_results.after_sampled_values_random_coeff);

        Self {}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cairo_air::utils::{deserialize_proof_from_file, ProofFormat};
    use cairo_plonk_dsl_data_structures::CairoProofVar;
    use cairo_plonk_dsl_hints::CairoFiatShamirHints;
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
        let fiat_shamir_hints = CairoFiatShamirHints::new(&proof);
        let proof_var = CairoProofVar::new_witness(&cs, &proof);
        let fiat_shamir_results = CairoFiatShamirResults::compute(&fiat_shamir_hints, &proof_var);
        let _ = AnswerResults::compute(&fiat_shamir_results, &proof_var.stark_proof);
    }
}
