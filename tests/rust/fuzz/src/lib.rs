#![allow(dead_code, unused_imports)]

use alloy_primitives::FixedBytes;
use alloy_sol_types::{sol, SolCall};
use solidity_merkle_trees_test::evm_runner::{EvmRunner, project_root};
use sp_core::KeccakHasher;
use sp_trie::{LayoutV0, MemoryDB, StorageProof};
use std::collections::HashSet;
use trie_db::{
    DBValue, Hasher, Recorder, Trie, TrieDBBuilder, TrieDBMutBuilder, TrieLayout, TrieMut,
};

sol! {
    struct StorageValue {
        bytes key;
        bytes value;
    }

    function VerifyKeys(bytes32 root, bytes[] proof, bytes[] keys) external pure returns (StorageValue[]);
}

fn data_sorted_unique(input: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut m = std::collections::BTreeMap::new();
    for (k, v) in input.into_iter() {
        let _ = m.insert(k, v);
    }
    m.into_iter().collect()
}

fn fuzz_to_data(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    let mut minkeylen = if let Some(v) = input.get(0) {
        let mut v = *v & 31u8;
        v = v + 1;
        v
    } else {
        return result;
    };
    let mut maxkeylen = if let Some(v) = input.get(1) {
        let mut v = *v & 31u8;
        v = v + 1;
        v
    } else {
        return result;
    };

    if maxkeylen < minkeylen {
        let v = minkeylen;
        minkeylen = maxkeylen;
        maxkeylen = v;
    }
    let mut ix = 2;
    loop {
        let keylen = if let Some(v) = input.get(ix) {
            let mut v = *v & 31u8;
            v = v + 1;
            v = std::cmp::max(minkeylen, v);
            v = std::cmp::min(maxkeylen, v);
            v as usize
        } else {
            break;
        };
        let key = if input.len() > ix + keylen { input[ix..ix + keylen].to_vec() } else { break };
        ix += keylen;
        let val = if input.len() > ix + 2 { input[ix..ix + 2].to_vec() } else { break };
        result.push((key, val));
    }
    result
}

fn test_generate_proof<L: TrieLayout>(
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    keys: Vec<Vec<u8>>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(Vec<u8>, Option<DBValue>)>) {
    let (db, root) = {
        let mut db = <MemoryDB<L::Hash>>::default();
        let mut root = Default::default();
        {
            let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
            for (key, value) in &entries {
                trie.insert(key, value).unwrap();
            }
        }
        (db, root)
    };

    let proof = {
        let mut recorder = Recorder::<L>::new();
        let trie_db = TrieDBBuilder::<L>::new(&db, &root).with_recorder(&mut recorder).build();

        for (key, expected) in &entries {
            let value = trie_db.get(key).unwrap().unwrap();
            assert_eq!(&value, expected);
        }

        let proof = recorder.drain().into_iter().map(|f| f.data).collect::<HashSet<_>>();
        {
            let mdb = StorageProof::new(proof.clone()).into_memory_db::<L::Hash>();
            let trie_db = TrieDBBuilder::<L>::new(&mdb, &root).build();
            for (key, expected) in &entries {
                let value = trie_db.get(key).unwrap().unwrap();
                assert_eq!(&value, expected);
            }
        }

        proof.into_iter().collect::<Vec<_>>()
    };

    let trie = TrieDBBuilder::<L>::new(&db, &root).build();
    let items = keys
        .into_iter()
        .map(|key| {
            let value = trie.get(&key).unwrap();
            (key, value)
        })
        .collect();

    (root, proof, items)
}

pub fn fuzz_that_verify_rejects_invalid_proofs(input: &[u8]) {
    if input.len() < 4 {
        return;
    }

    let random_int = u32::from_le_bytes(input[0..4].try_into().expect("slice is 4 bytes")) as usize;

    let mut data = fuzz_to_data(&input[4..]);
    let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
    data.truncate(data.len() * 2 / 3);

    let data = data_sorted_unique(data);
    keys.sort();
    keys.dedup();

    if keys.is_empty() {
        return;
    }

    let (root, proof, mut items) = test_generate_proof::<LayoutV0<KeccakHasher>>(data, keys);

    if proof.is_empty() {
        return;
    }

    // Make all items incorrect.
    for i in 0..items.len() {
        match &mut items[i] {
            (_, Some(value)) if random_int % 2 == 0 => value.push(0),
            (_, value) if value.is_some() => *value = None,
            (_, value) => *value = Some(DBValue::new()),
        }
    }

    let project = project_root();
    let mut runner = EvmRunner::new();
    let addr = runner.deploy(&project, "MerklePatriciaTest");

    for (key, value) in items {
        let call = VerifyKeysCall {
            root: FixedBytes(root.into()),
            proof: proof.clone().into_iter().map(Into::into).collect(),
            keys: vec![key.into()],
        };
        let result_bytes = runner.call_raw(addr, call.abi_encode());
        let decoded = VerifyKeysCall::abi_decode_returns(&result_bytes, true).unwrap();
        let result =
            if decoded._0[0].value.is_empty() { None } else { Some(decoded._0[0].value.to_vec()) };

        assert_ne!(result, value);
    }
}

pub fn fuzz_that_verify_accepts_valid_proofs(input: &[u8]) {
    let mut data = fuzz_to_data(input);
    let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
    data.truncate(data.len() * 2 / 3);

    let data = data_sorted_unique(data);
    keys.sort();
    keys.dedup();

    let (root, proof, items) = test_generate_proof::<LayoutV0<KeccakHasher>>(data, keys);

    if proof.is_empty() {
        return;
    }

    let project = project_root();
    let mut runner = EvmRunner::new();
    let addr = runner.deploy(&project, "MerklePatriciaTest");

    for (key, value) in items {
        let call = VerifyKeysCall {
            root: FixedBytes(root.into()),
            proof: proof.clone().into_iter().map(Into::into).collect(),
            keys: vec![key.into()],
        };
        let result_bytes = runner.call_raw(addr, call.abi_encode());
        let decoded = VerifyKeysCall::abi_decode_returns(&result_bytes, true).unwrap();
        let result =
            if decoded._0[0].value.is_empty() { None } else { Some(decoded._0[0].value.to_vec()) };

        assert_eq!(result, value);
    }
}
