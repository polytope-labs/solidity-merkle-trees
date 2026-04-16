#![allow(unused_parens, dead_code)]

pub mod evm_runner;
pub mod merkle_mountain_range;
pub mod merkle_multi_proof;
pub mod merkle_patricia;
pub mod multi_proof_utils;

use alloy_primitives::keccak256;
use ckb_merkle_mountain_range::{Error, Merge};
use rs_merkle::Hasher;

#[derive(Clone)]
pub struct Keccak256;

impl Hasher for Keccak256 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        keccak256(data).0
    }
}

pub struct MergeKeccak;

impl Merge for MergeKeccak {
    type Item = NumberHash;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Result<Self::Item, Error> {
        let mut concat = vec![];
        concat.extend(&lhs.0);
        concat.extend(&rhs.0);
        let hash = keccak256(&concat);
        Ok(NumberHash(hash.0.to_vec()))
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Default)]
pub struct NumberHash(pub Vec<u8>);

impl From<u32> for NumberHash {
    fn from(num: u32) -> Self {
        let hash = keccak256(&num.to_le_bytes());
        NumberHash(hash.0.to_vec())
    }
}
