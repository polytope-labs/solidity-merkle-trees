#![no_main]

use libfuzzer_sys::fuzz_target;
use solidity_merkle_trees_fuzz::fuzz_that_verify_accepts_valid_proofs;

fuzz_target!(|data: &[u8]| {
    fuzz_that_verify_accepts_valid_proofs(data);
});
