use bzip2::read::BzDecoder;
use cairo_air::{verifier::verify_cairo, CairoProof, PreProcessedTraceVariant};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_traits::One;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use stwo::core::vcs::poseidon31_merkle::Poseidon31MerkleHasher;
use stwo::core::{
    fields::qm31::QM31, fri::FriConfig, pcs::PcsConfig, vcs::poseidon31_hash::Poseidon31Hash,
    vcs::poseidon31_merkle::Poseidon31MerkleChannel,
};
use stwo_examples::plonk_with_poseidon::air::{verify_plonk_with_poseidon, PlonkWithPoseidonProof};

fn bench_verify_initial_stark_proof(c: &mut Criterion) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let data_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("cairo-components")
        .join("test_data")
        .join("recursive_proof.bin.bz");

    // Read and decompress the file once into memory
    let proof_file = File::open(&data_path).unwrap();
    let mut bz_decoder = BzDecoder::new(proof_file);
    let mut proof_bytes = Vec::new();
    bz_decoder.read_to_end(&mut proof_bytes).unwrap();

    c.bench_function("verify_initial_stark_proof", |b| {
        b.iter_batched(
            || {
                // Setup: deserialize from in-memory bytes (not timed)
                bincode::deserialize::<CairoProof<Poseidon31MerkleHasher>>(&proof_bytes).unwrap()
            },
            |proof| {
                // Benchmark: only this is timed
                verify_cairo::<Poseidon31MerkleChannel>(
                    black_box(proof),
                    black_box(PreProcessedTraceVariant::CanonicalWithoutPedersen),
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        )
    });
}

fn bench_verify_last_recursion_proof(c: &mut Criterion) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");

    // Load the last recursion proof
    let proof_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join("level5_28_7_9.bin");

    // Load output_hash
    let output_hash_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("data")
        .join("output_hash.txt");
    let output_hash =
        serde_json::from_str::<Poseidon31Hash>(&std::fs::read_to_string(output_hash_path).unwrap())
            .unwrap();

    // Setup config and inputs
    let dest_config = PcsConfig {
        pow_bits: 28,
        fri_config: FriConfig::new(7, 9, 8),
    };

    let inputs = vec![
        (1, QM31::one()),
        (2, QM31::from_u32_unchecked(0, 1, 0, 0)),
        (3, QM31::from_u32_unchecked(0, 0, 1, 0)),
        (
            4,
            QM31::from_m31(
                output_hash.0[0],
                output_hash.0[1],
                output_hash.0[2],
                output_hash.0[3],
            ),
        ),
        (
            5,
            QM31::from_m31(
                output_hash.0[4],
                output_hash.0[5],
                output_hash.0[6],
                output_hash.0[7],
            ),
        ),
    ];

    // Load the proof once
    let mut fs = std::fs::File::open(&proof_path).unwrap();
    let proof: PlonkWithPoseidonProof<Poseidon31MerkleHasher> =
        bincode::deserialize_from(&mut fs).unwrap();

    c.bench_function("verify_last_recursion_proof", |b| {
        b.iter(|| {
            verify_plonk_with_poseidon::<Poseidon31MerkleChannel>(
                black_box(proof.clone()),
                black_box(dest_config),
                black_box(&inputs),
            )
            .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_verify_initial_stark_proof,
    bench_verify_last_recursion_proof
);
criterion_main!(benches);
