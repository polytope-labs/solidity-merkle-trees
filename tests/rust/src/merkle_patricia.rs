#![cfg(test)]
#![allow(dead_code, unused_imports)]

use crate::evm_runner::{EvmRunner, project_root};
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use codec::Decode;
use hex_literal::hex;
use primitive_types::H256;
use sp_core::KeccakHasher;
use sp_trie::{LayoutV0, MemoryDB, NodeCodec, StorageProof};
use std::collections::HashSet;
use trie_db::{
    DBValue, Hasher, NodeCodec as NodeCodecT, Recorder, Trie, TrieDBBuilder, TrieDBMutBuilder,
    TrieLayout, TrieMut,
};

sol! {
    struct StorageValue {
        bytes key;
        bytes value;
    }

    struct SolNibbleSlice {
        bytes data;
        uint256 offset;
    }

    struct SolByteSlice {
        bytes data;
        uint256 offset;
    }

    struct SolNodeHandle {
        bool isHash;
        bytes32 hash;
        bool isInline;
        bytes inLine;
    }

    struct SolNodeHandleOption {
        bool isSome;
        SolNodeHandle value;
    }

    struct SolNodeKind {
        bool isEmpty;
        bool isLeaf;
        bool isHashedLeaf;
        bool isNibbledValueBranch;
        bool isNibbledHashedValueBranch;
        bool isNibbledBranch;
        bool isExtension;
        bool isBranch;
        uint256 nibbleSize;
        SolByteSlice data;
    }

    function VerifyKeys(bytes32 root, bytes[] proof, bytes[] keys) external pure returns (StorageValue[]);
    function VerifyEthereum(bytes32 root, bytes[] proof, bytes[] keys) external pure returns (StorageValue[]);
    function decodeNodeKind(bytes node) external pure returns (SolNodeKind);
    function decodeNibbledBranch(bytes node) external;
    function decodeLeaf(bytes node) external;
    function nibbleLen(SolNibbleSlice nibble) external pure returns (uint256);
    function isNibbleEmpty(SolNibbleSlice self_) external pure returns (bool);
    function nibbleAt(SolNibbleSlice self_, uint256 i) external pure returns (uint256);
    function mid(SolNibbleSlice self_, uint256 i) external pure returns (SolNibbleSlice);
    function commonPrefix(SolNibbleSlice self_, SolNibbleSlice other) external pure returns (uint256);
    function startsWith(SolNibbleSlice self_, SolNibbleSlice other) external pure returns (bool);
    function eq(SolNibbleSlice self_, SolNibbleSlice other) external pure returns (bool);
}

fn proof_data() -> ([u8; 32], Vec<Vec<u8>>, Vec<u8>) {
    let key = hex!("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb").to_vec();
    let proof = vec![
        hex!("802e98809b03c6ae83e3b70aa89acfe0947b3a18b5d35569662335df7127ab8fcb88c88780e5d1b21c5ecc2891e3467f6273f27ce2e73a292d6b8306197edfa97b3d965bd080c51e5f53a03d92ea8b2792218f152da738b9340c6eeb08581145825348bbdba480ad103a9320581c7747895a01d79d2fa5f103c4b83c5af10b0a13bc1749749523806eea23c0854ced8445a3338833e2401753fdcfadb3b56277f8f1af4004f73719806d990657a5b5c3c97b8a917d9f153cafc463acd90592f881bc071d6ba64e90b380346031472f91f7c44631224cb5e61fb29d530a9fafd5253551cbf43b7e97e79a").to_vec(),
        hex!("9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2035e90c7f86010000").to_vec(),
    ];

    let root = hex!("6b5710000eccbd59b6351fc2eb53ff2c1df8e0f816f7186ddd309ca85e8798dd");

    (root, proof, key)
}

fn setup() -> (EvmRunner, alloy_primitives::Address) {
    let root = project_root();
    let mut runner = EvmRunner::new();
    let addr = runner.deploy(&root, "MerklePatriciaTest");
    (runner, addr)
}

fn make_nibble(data: &[u8], offset: u64) -> SolNibbleSlice {
    SolNibbleSlice {
        data: data.to_vec().into(),
        offset: U256::from(offset),
    }
}

#[test]
fn test_decode_nibbled_branch() {
    let (mut runner, addr) = setup();
    let (_, proof, _) = proof_data();

    for item in proof {
        let _plan = NodeCodec::<KeccakHasher>::decode_plan(&mut &item[..]).unwrap().build(&item);

        let call = decodeNodeKindCall {
            node: item.clone().into(),
        };
        let result = runner.call_raw(addr, call.abi_encode());
        let decoded = decodeNodeKindCall::abi_decode_returns(&result, true).unwrap();
        assert!(decoded._0.isNibbledBranch);

        // Just check decodeNibbledBranch doesn't revert
        let call = decodeNibbledBranchCall {
            node: item.clone().into(),
        };
        runner.call_raw(addr, call.abi_encode());
    }
}

#[test]
fn test_decode_leaf() {
    let leaves: Vec<Vec<u8>> = vec![
        vec![95, 14, 123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41, 8, 0, 0],
        vec![
            95, 15, 31, 5, 21, 244, 98, 205, 207, 132, 224, 241, 214, 4, 93, 252, 187, 32, 240,
            214, 144, 122, 134, 1, 0, 0,
        ],
    ];
    let (mut runner, addr) = setup();

    for leaf in leaves {
        let _plan = NodeCodec::<KeccakHasher>::decode_plan(&mut &leaf[..]).unwrap().build(&leaf);

        let call = decodeNodeKindCall {
            node: leaf.clone().into(),
        };
        let result = runner.call_raw(addr, call.abi_encode());
        let decoded = decodeNodeKindCall::abi_decode_returns(&result, true).unwrap();
        assert!(decoded._0.isLeaf);

        // Just check decodeLeaf doesn't revert
        let call = decodeLeafCall {
            node: leaf.clone().into(),
        };
        runner.call_raw(addr, call.abi_encode());
    }
}

static D: &[u8; 3] = &[0x01u8, 0x23, 0x45];

#[test]
fn test_nibble_slice_ops_basics() {
    let (mut runner, addr) = setup();

    // nibbleLen with offset 0
    let call = nibbleLenCall { nibble: make_nibble(D, 0) };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = nibbleLenCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(decoded._0, U256::from(6));

    // isNibbleEmpty with offset 0
    let call = isNibbleEmptyCall { self_: make_nibble(D, 0) };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = isNibbleEmptyCall::abi_decode_returns(&result, true).unwrap();
    assert!(!decoded._0);

    // isNibbleEmpty with offset 6
    let call = isNibbleEmptyCall { self_: make_nibble(D, 6) };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = isNibbleEmptyCall::abi_decode_returns(&result, true).unwrap();
    assert!(decoded._0);

    // nibbleLen with offset 3
    let call = nibbleLenCall { nibble: make_nibble(D, 3) };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = nibbleLenCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(decoded._0, U256::from(3));

    // nibbleAt with offset 3
    for i in 0u64..3 {
        let call = nibbleAtCall {
            self_: make_nibble(D, 3),
            i: U256::from(i),
        };
        let result = runner.call_raw(addr, call.abi_encode());
        let decoded = nibbleAtCall::abi_decode_returns(&result, true).unwrap();
        assert_eq!(decoded._0, U256::from(i + 3));
    }
}

#[test]
fn test_nibble_slice_ops_mid() {
    let (mut runner, addr) = setup();

    // mid(D, 2)
    let call = midCall {
        self_: make_nibble(D, 0),
        i: U256::from(2),
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let nibble = midCall::abi_decode_returns(&result, true).unwrap()._0;

    for i in 0u64..4 {
        let call = nibbleAtCall {
            self_: nibble.clone(),
            i: U256::from(i),
        };
        let result = runner.call_raw(addr, call.abi_encode());
        let decoded = nibbleAtCall::abi_decode_returns(&result, true).unwrap();
        assert_eq!(decoded._0, U256::from(i + 2));
    }

    // mid(D, 3)
    let call = midCall {
        self_: make_nibble(D, 0),
        i: U256::from(3),
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let nibble = midCall::abi_decode_returns(&result, true).unwrap()._0;

    for i in 0u64..3 {
        let call = nibbleAtCall {
            self_: nibble.clone(),
            i: U256::from(i),
        };
        let result = runner.call_raw(addr, call.abi_encode());
        let decoded = nibbleAtCall::abi_decode_returns(&result, true).unwrap();
        assert_eq!(decoded._0, U256::from(i + 3));
    }
}

#[test]
fn test_nibble_slice_ops_shared() {
    let (mut runner, addr) = setup();
    let n = make_nibble(D, 0);

    let other = &[0x01u8, 0x23, 0x01, 0x23, 0x45, 0x67];
    let m = make_nibble(other, 0);

    // commonPrefix(n, m) == 4
    let call = commonPrefixCall { self_: n.clone(), other: m.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert_eq!(commonPrefixCall::abi_decode_returns(&result, true).unwrap()._0, U256::from(4));

    // commonPrefix(m, n) == 4
    let call = commonPrefixCall { self_: m.clone(), other: n.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert_eq!(commonPrefixCall::abi_decode_returns(&result, true).unwrap()._0, U256::from(4));

    // m_mid_4 = mid(m, 4)
    let call = midCall { self_: m.clone(), i: U256::from(4) };
    let result = runner.call_raw(addr, call.abi_encode());
    let m_mid_4 = midCall::abi_decode_returns(&result, true).unwrap()._0;

    // startsWith(m_mid_4, n) == true
    let call = startsWithCall { self_: m_mid_4.clone(), other: n.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert!(startsWithCall::abi_decode_returns(&result, true).unwrap()._0);

    // startsWith(n, m_mid_4) == false
    let call = startsWithCall { self_: n.clone(), other: m_mid_4.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert!(!startsWithCall::abi_decode_returns(&result, true).unwrap()._0);

    // commonPrefix(n, m_mid_4) == 6
    let call = commonPrefixCall { self_: n.clone(), other: m_mid_4.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert_eq!(commonPrefixCall::abi_decode_returns(&result, true).unwrap()._0, U256::from(6));

    // n_mid_1 = mid(n, 1), m_mid_1 = mid(m, 1), m_mid_2 = mid(m, 2)
    let call = midCall { self_: n.clone(), i: U256::from(1) };
    let result = runner.call_raw(addr, call.abi_encode());
    let n_mid_1 = midCall::abi_decode_returns(&result, true).unwrap()._0;

    let call = midCall { self_: m.clone(), i: U256::from(1) };
    let result = runner.call_raw(addr, call.abi_encode());
    let m_mid_1 = midCall::abi_decode_returns(&result, true).unwrap()._0;

    let call = midCall { self_: m.clone(), i: U256::from(2) };
    let result = runner.call_raw(addr, call.abi_encode());
    let m_mid_2 = midCall::abi_decode_returns(&result, true).unwrap()._0;

    // commonPrefix(n_mid_1, m_mid_1) == 3
    let call = commonPrefixCall { self_: n_mid_1.clone(), other: m_mid_1.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert_eq!(commonPrefixCall::abi_decode_returns(&result, true).unwrap()._0, U256::from(3));

    // commonPrefix(n_mid_1, m_mid_2) == 0
    let call = commonPrefixCall { self_: n_mid_1.clone(), other: m_mid_2.clone() };
    let result = runner.call_raw(addr, call.abi_encode());
    assert_eq!(commonPrefixCall::abi_decode_returns(&result, true).unwrap()._0, U256::from(0));
}

#[test]
fn test_merkle_patricia_trie() {
    let (root, proof, key) = proof_data();
    let (mut runner, addr) = setup();

    let call = VerifyKeysCall {
        root: FixedBytes(root),
        proof: proof.into_iter().map(Into::into).collect(),
        keys: vec![key.into()],
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = VerifyKeysCall::abi_decode_returns(&result, true).unwrap();

    let value = &decoded._0[0].value;
    let timestamp = <u64>::decode(&mut &value[..]).unwrap();
    assert_eq!(timestamp, 1_677_168_798_005);
}

fn generate_proof<L: TrieLayout>(
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(Vec<u8>, Option<DBValue>)>) {
    let keys = (0..10).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();
    let values = (0..10).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();

    let entries = keys.clone().into_iter().zip(values.clone().into_iter()).collect::<Vec<_>>();
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

#[test]
fn test_merkle_patricia_trie_layout_v0() {
    let (root, proof, entries) = generate_proof::<LayoutV0<KeccakHasher>>();
    let (mut runner, addr) = setup();

    for (key, value) in entries {
        let call = VerifyKeysCall {
            root: FixedBytes(root.into()),
            proof: proof.clone().into_iter().map(Into::into).collect(),
            keys: vec![key.into()],
        };
        let result = runner.call_raw(addr, call.abi_encode());
        let decoded = VerifyKeysCall::abi_decode_returns(&result, true).unwrap();
        assert_eq!(decoded._0[0].value.to_vec(), value.unwrap());
    }

    // non-membership proof
    let call = VerifyKeysCall {
        root: FixedBytes(root.into()),
        proof: proof.into_iter().map(Into::into).collect(),
        keys: vec![H256::random().as_bytes().to_vec().into()],
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = VerifyKeysCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(decoded._0[0].value.len(), 0);
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_transaction_trie_single_node() {
    let (mut runner, addr) = setup();

    let call = VerifyEthereumCall {
        root: FixedBytes(hex!("ecabc214ab6c55e1342e888fa677e2bcc29218a4b248a56fcebf7aa357807b60")),
        proof: vec![
            hex!("f89b822080b89601f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec().into(),
        ],
        keys: vec![hex!("80").to_vec().into()],
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = VerifyEthereumCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(
        decoded._0[0].value.to_vec(),
        hex!("01f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec()
    );
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_transaction_trie_multi_node() {
    let (mut runner, addr) = setup();

    let call = VerifyEthereumCall {
        root: FixedBytes(hex!("ac39df3a470f95659f9f6f30c4de252479ddd4e6083ba7a7be72d2505b4062e2")),
        proof: vec![
            hex!("f90131a0abd3b92264de818dd5c44b3212ee3d20de2478ca6a080d59b0f7eadc165aea33a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a06bae3f278b07352be6e823e9c9584d2a8ba01e000cc7653b5b1d213888b841548080808080808080").to_vec().into(),
            hex!("f871a036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da060c25b7b04d23c401c874963020e932bcafdef5b9b5c4f25394e2c3bba644feca06cf2dabf824eee4758b57a77612e1f7a0d483e3656d9a76ea7b11a70a50dd4008080808080808080808080808080").to_vec().into(),
            hex!("f8b1a0cb8fc8ea7d198bd1b6fb48a51e17932ad8333ef0b57b17326fbe3c4f6abf231ea018c89cbf38ef1aa86fc642cfc5eae17f49aef97c493c5ada614743d630de32fba018c89cbf38ef1aa86fc642cfc5eae17f49aef97c493c5ada614743d630de32fba018c89cbf38ef1aa86fc642cfc5eae17f49aef97c493c5ada614743d630de32fba0951955209df36420e52fc0961cba8318a288676262651f9e7cdafd0cf177c1e5808080808080808080808080").to_vec().into(),
            hex!("f90211a03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aa80").to_vec().into(),
            hex!("f90211a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd180").to_vec().into(),
            hex!("f90211a036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036d80").to_vec().into(),
            hex!("f89920b89601f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec().into(),
        ],
        keys: vec![hex!("8232c8").to_vec().into()],
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = VerifyEthereumCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(
        decoded._0[0].value.to_vec(),
        hex!("01f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec()
    );
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_state_trie_single_node() {
    let (mut runner, addr) = setup();

    let call = VerifyEthereumCall {
        root: FixedBytes(hex!("0ce23f3c809de377b008a4a3ee94a0834aac8bec1f86e28ffe4fdb5a15b0c785")),
        proof: vec![
            hex!("f86aa1205380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab846f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec().into(),
        ],
        keys: vec![hex!("5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a").to_vec().into()],
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = VerifyEthereumCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(
        decoded._0[0].value.to_vec(),
        hex!("f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()
    );
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_state_trie_multi_node() {
    let (mut runner, addr) = setup();

    let call = VerifyEthereumCall {
        root: FixedBytes(hex!("4dc3e58e944d713c36c6b9cc58df023b3e578093de16e175faefa8f91727ca6e")),
        proof: vec![
            hex!("f90211a07466452b9c24acc76f0c9a0a4d43f5b362a031626eb6a0d7e7409c9c2fe1ecdda00bc98d4eaa34347ecb42d4d716161612692c2ac599cf3c4f5eade18fbb07da4ca00146ab246da36aec011dcdf8fd4c6a505ec7caca75441268c7eab80e9aa96767a038a41d42f1edccf59f2a1d6e7887ab1f3dfcd0a26f3be309ee237ed4aecd9d38a05f542a7ffff85163015c7cfc8c7d947ac98114f1bc576ab74ec663dd97d9596fa0208cb7384b248a341c22ef52d1882f6045345c6435c38a5b4d382e7a02c53f48a086b590086c7e7738c59cd0bba1a136dc42cc099fa9ae8af77abaa76fa1f3f503a0ab69ef5e7d461a547675de48c30be16f2d297509f6d005325365cbebe8735104a0896573c4595ea56992cb4237091ce8f00a73988f80506ef7bde78de9cfddbfa9a06d78ae475034b4aec9afef58c3f93e997f2c50f2a4948a7214b0295c5ae1776ea0763c0ec3ea13b7cbfe139cf8a3cf76e75026b2d42854bf822a47a0497dabf679a028fd50ebf9eed4e9a0969a73682ea615cb1134510f80aa057c60acf657a13a05a00c9f1e12244dabf2db619f0ce1098dd6d19f7c9dd1b17da1ffd02b0e0f3d4d7ea0aa2a772e989b23bd7e2eba714f153031c79c03cb835539fc56debc7669b64148a07f6544adbc5e30eca006a050384d85df7a510bac66dde8c32b7741486b319610a0c859cc09be23308083a16f96c19dffd9b48770b715c150220a35e07ff5ea716b80").to_vec().into(),
            hex!("f90171a02ffa31221e3db9f56751599b181b16cd0489d9870f58a481ee1398d6991a6ed3a0af7f7b8a8aa219ebd9e9562bd3f917c47f7205bb0f29bdb064c63e51f8e14ee680a0fc0482eb10e5eccc57013233746a95072c2d80746898c30a23fc43c52eabddf5a0985b92a5617ee65b05be517cbbeb1c5598e5479bdb45107552b80d339c6c23eba0984d7ace51d61b40d4336aec39c867fc5db4566036ef0e6225df604dd93a6538a068ff593d5fc203763242dc6b95e559472f8d43ceed1a4fececb11a0eb6ef1070a0d7a609f017d3641ff18327916212ebf21d6ae93b3ffe09ae6fc5e1160c7f571f80a0d62e9137db3e883d506c3927310d0100e624b5befe180830f029c99859451230a0ce9a78f4d5abb17cfe7c189a83524a479bd8aed870cc7608c3ede431cdd214cd8080a0f58d48fa8ca7b152aa825128a173c6061b6cabe9143473e246f6d8732f59cc3880a030a23d0cd92c346ce27019e17ddbf8651695cd3fd6350f0f7862f915269a57ff80").to_vec().into(),
            hex!("f8518080808080808080a0fed0c7841e83453b78135ca2a36e8fb5d8c5fbb5883746f3f93054e42205e7e880808080a0711f6aa6ad472844f3e563a1c3ff5777c4e2c3b3126b42fa4eb4d115546116c5808080").to_vec().into(),
            hex!("f8689f30c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab846f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec().into(),
        ],
        keys: vec![hex!("5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a").to_vec().into()],
    };
    let result = runner.call_raw(addr, call.abi_encode());
    let decoded = VerifyEthereumCall::abi_decode_returns(&result, true).unwrap();
    assert_eq!(
        decoded._0[0].value.to_vec(),
        hex!("f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()
    );
}
