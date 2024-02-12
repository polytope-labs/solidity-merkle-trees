#![allow(dead_code, unused_imports)]

use patricia_merkle_trie::{MemoryDB, StorageProof};
use solidity_merkle_trees_test::Token;
use sp_core::KeccakHasher;
use sp_trie::LayoutV0;
use std::collections::HashSet;
use trie_db::{
    DBValue, Hasher, Recorder, Trie, TrieDBBuilder, TrieDBMutBuilder, TrieLayout, TrieMut,
};

fn data_sorted_unique(input: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut m = std::collections::BTreeMap::new();
    for (k, v) in input.into_iter() {
        let _ = m.insert(k, v); // latest value for uniqueness
    }
    m.into_iter().collect()
}

fn fuzz_to_data(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    // enc = (minkeylen, maxkeylen (min max up to 32), datas)
    // fix data len 2 bytes
    let mut minkeylen = if let Some(v) = input.get(0) {
        let mut v = *v & 31u8;
        v = v + 1;
        v
    } else {
        return result
    };
    let mut maxkeylen = if let Some(v) = input.get(1) {
        let mut v = *v & 31u8;
        v = v + 1;
        v
    } else {
        return result
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
            break
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
    // Populate DB with full trie from entries.
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

    // Generate proof for the given keys..
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
        return
    }

    let random_int = u32::from_le_bytes(input[0..4].try_into().expect("slice is 4 bytes")) as usize;

    let mut data = fuzz_to_data(&input[4..]);
    // Split data into 3 parts:
    // - the first 1/3 is added to the trie and not included in the proof
    // - the second 1/3 is added to the trie and included in the proof
    // - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
    let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
    data.truncate(data.len() * 2 / 3);

    let data = data_sorted_unique(data);
    keys.sort();
    keys.dedup();

    if keys.is_empty() {
        return
    }

    let (root, proof, mut items) = test_generate_proof::<LayoutV0<KeccakHasher>>(data, keys);

    if proof.len() == 0 {
        return
    }

    // Make all items incorrect.
    for i in 0..items.len() {
        match &mut items[i] {
            (_, Some(value)) if random_int % 2 == 0 => value.push(0),
            (_, value) if value.is_some() => *value = None,
            (_, value) => *value = Some(DBValue::new()),
        }
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = forge_testsuite::Runner::new(PathBuf::from(&base_dir));

    runtime.block_on(async move {
        let mut contract = runner.deploy("MerklePatriciaTest").await;
        for (key, value) in items {
            let result = contract
                .call::<_, Vec<(Vec<u8>, Vec<u8>)>>(
                    "VerifyKeys",
                    (
                        Token::FixedBytes(root.as_ref().to_vec()),
                        Token::Array(proof.clone().into_iter().map(Token::Bytes).collect()),
                        Token::Array(vec![Token::Bytes(key.to_vec())]),
                    ),
                )
                .await
                .unwrap();
            let result = if result[0].1.len() == 0 { None } else { Some(result[0].1.clone()) };

            assert_ne!(result, value);
        }
    });
}

pub fn fuzz_that_verify_accepts_valid_proofs(input: &[u8]) {
    let mut data = fuzz_to_data(input);
    // Split data into 3 parts:
    // - the first 1/3 is added to the trie and not included in the proof
    // - the second 1/3 is added to the trie and included in the proof
    // - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
    let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
    data.truncate(data.len() * 2 / 3);

    let data = data_sorted_unique(data);
    keys.sort();
    keys.dedup();

    let (root, proof, items) = test_generate_proof::<LayoutV0<KeccakHasher>>(data, keys);

    if proof.len() == 0 {
        return
    }

    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = forge_testsuite::Runner::new(PathBuf::from(&base_dir));
    let runtime = tokio::runtime::Runtime::new().unwrap();

    runtime.block_on(async move {
        let mut contract = runner.deploy("MerklePatriciaTest").await;
        for (key, value) in items {
            let result = contract
                .call::<_, Vec<(Vec<u8>, Vec<u8>)>>(
                    "VerifyKeys",
                    (
                        Token::FixedBytes(root.as_ref().to_vec()),
                        Token::Array(proof.clone().into_iter().map(Token::Bytes).collect()),
                        Token::Array(vec![Token::Bytes(key.to_vec())]),
                    ),
                )
                .await
                .unwrap();
            let result = if result[0].1.len() == 0 { None } else { Some(result[0].1.clone()) };
            assert_eq!(result, value)
        }
    });
}
