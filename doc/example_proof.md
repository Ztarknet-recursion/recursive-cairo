# Example Proof

This markdown describes the Cairo proof that is being recursively verified.

## SNOS proof

[Zebra](https://github.com/Ztarknet/zebra) first [invokes](https://github.com/Ztarknet/zebra/blob/zfuture/zebra-prove/src/generate_pie.rs) Starknet OS (called [SNOS](https://github.com/keep-starknet-strange/snos/))  to generate Cairo PIE (position-independent executions) that verifies the desired ranges of the blocks on a given Starknet network. 

Then, it uses [stwo_run_and_prove](https://github.com/starkware-libs/proving-utils/) to generate a proof. This uses blake2s as the hash function and `canonical` preprocessed trace, with the following config: pow_bits = 26, log_last_layer_degree_bound = 0, log_blowup_factor = 1, and n_queries = 70.

The output of this SNOS proof consists of the [OsOutputHeader](https://github.com/Ztarknet/zebra/blob/zfuture/zebra-prove/src/proof_utils.rs), which includes state roots, block hashes, and other information that summarizes the execution of the SNOS, and some other outputs for data availability (DA). The example here has 54 outputs, each of [u32; 8]. 


## Verify the SNOS proof in Cairo

[Our fork of Zebra](https://github.com/Ztarknet-recursion/zebra-fork) then uses an existing Cairo program to verify this SNOS proof and generates a proof of this verification.

```rust
use stwo_cairo_air::{CairoProof, VerificationOutput, get_verification_output, verify_cairo};

#[executable]
fn main(proof: CairoProof) -> VerificationOutput {
    let output = get_verification_output(proof: @proof);
    verify_cairo(proof);
    output
}
```

Because we use the `blake_outputs_packing` feature, the 54 outputs from the SNOS proof will be hashed to a single Blake2s hash. This Cairo program uses [the simple bootloader](https://github.com/Ztarknet-recursion/zebra-fork/blob/m-kus/compress-proof/zebra-prove/bootloaders/simple_bootloader_compiled.json), with feature flags `qm31_opcode` and `blake_outputs_packing` and the config with pow_bits = 26, log_last_layer_degree_bound = 0, log_blowup_factor = 1, and n_queries = 70. 

It has five outputs (each of [u32; 8]) as follows:
   * The 1st output is 1, representing that 1 task has been [executed](https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/bootloaders/simple_bootloader/simple_bootloader.cairo#L80)
   * The 2nd output is 4, representing that this task has [4 - 2 = 2 outputs](https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/bootloaders/simple_bootloader/execute_task.cairo#L299).
   * The 3rd output is the program hash of the Blake2s hash of the [Cairo-to-Cairo recursive verifier][cairo-recursive-verifier]'s binary code. This hash is computed and appended to the output by the simple bootloader.
   * The 4th output is the program hash of the Blake2s hash of [a Starknet OS (SNOS) Cairo program][snos]. This hash is computed and appended to the output by the Cairo-to-Cairo recursive verifier.
   * The 5th output is the Blake2s hash of the outputs of the SNOS Cairo program.

One may consider reducing the size of this proof by increasing the log_blowup_factor, but in practice we have two observations:

- The verifier circuit is already big enough, and there is a limited selection of log_blowup_factor before reaching the Circle-Stwo bound.
- The proof generation slows down significantly when log_blowup_factor is increased because it is using a lot of memory that some smaller machines would fail to generate the proof.

Therefore, it motivates us to use a different proof system with smaller layouts (Plonk with Poseidon) to recursively verify this Cairo proof to reduce the proof sizes further. 

[cairo-recursive-verifier]: https://github.com/Ztarknet-recursion/zebra-fork/blob/m-kus/compress-proof/zebra-prove/recursion/src/lib.cairo

[snos]: https://github.com/keep-starknet-strange/snos