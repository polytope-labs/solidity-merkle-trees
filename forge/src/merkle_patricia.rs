#![cfg(test)]
#![allow(dead_code, unused_imports)]

use crate::forge::{execute, runner};
use codec::Decode;
use ethers::abi::{Token, Uint};
use hex_literal::hex;
use sp_core::KeccakHasher;
use sp_trie::NodeCodec;
use trie_db::NodeCodec as NodeCodecT;

type Slice = (
    Vec<u8>, // data;
    Uint,    // offset;
);

type NodeHandle = (
    bool,     // isHash;
    [u8; 32], // hash;
    bool,     // isInline;
    Vec<u8>,  // inLine;
);

type NodeHandleOption = (
    bool,       // isSome,
    NodeHandle, // value
);

type NibbledBranch = (
    Slice,                  // key;
    NodeHandleOption,       // value;
    [NodeHandleOption; 16], // children;
);

type NodeKind = (
    bool, // isEmpty;
    bool, // isLeaf;
    bool, // isHashedLeaf;
    bool, // isNibbledValueBranch;
    bool, // isNibbledHashedValueBranch;
    bool, // isNibbledBranch;
    bool, // isExtension;
    bool, // isBranch;
    Uint, // nibbleSize;
    Slice,
);

fn proof_data() -> ([u8; 32], Vec<Vec<u8>>, Vec<u8>) {
    let key = hex!("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb").to_vec();
    let proof = vec![
        hex!("802e98809b03c6ae83e3b70aa89acfe0947b3a18b5d35569662335df7127ab8fcb88c88780e5d1b21c5ecc2891e3467f6273f27ce2e73a292d6b8306197edfa97b3d965bd080c51e5f53a03d92ea8b2792218f152da738b9340c6eeb08581145825348bbdba480ad103a9320581c7747895a01d79d2fa5f103c4b83c5af10b0a13bc1749749523806eea23c0854ced8445a3338833e2401753fdcfadb3b56277f8f1af4004f73719806d990657a5b5c3c97b8a917d9f153cafc463acd90592f881bc071d6ba64e90b380346031472f91f7c44631224cb5e61fb29d530a9fafd5253551cbf43b7e97e79a").to_vec(),
        hex!("9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2035e90c7f86010000").to_vec(),
    ];

    let root = hex!("6b5710000eccbd59b6351fc2eb53ff2c1df8e0f816f7186ddd309ca85e8798dd");

    (root, proof, key)
}

#[test]
fn test_decode_nibbled_branch() {
    let mut runner = runner();

    let (_, proof, _) = proof_data();

    for item in proof.clone() {
        let plan = NodeCodec::<KeccakHasher>::decode_plan(&mut &item[..]).unwrap().build(&item);

        println!("{:?}", plan);

        let result = execute::<_, NodeKind>(
            &mut runner,
            "MerklePatriciaTest",
            "decodeNodeKind",
            (Token::Bytes(item.clone())),
        )
        .unwrap();

        assert!(result.5); // isNibbledBranch

        let result = execute::<_, Token>(
            &mut runner,
            "MerklePatriciaTest",
            "decodeNibbledBranch",
            (Token::Bytes(item.clone())),
        )
        .unwrap();

        println!("decodeNibbledBranch: {:?}", &result);

        println!("\n\n\n");
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
    let mut runner = runner();

    for leaf in leaves {
        let plan = NodeCodec::<KeccakHasher>::decode_plan(&mut &leaf[..]).unwrap().build(&leaf);

        println!("{:#?}", plan);

        let result = execute::<_, NodeKind>(
            &mut runner,
            "MerklePatriciaTest",
            "decodeNodeKind",
            (Token::Bytes(leaf.clone())),
        )
        .unwrap();

        assert!(result.1); // isLeaf

        let result = execute::<_, Token>(
            &mut runner,
            "MerklePatriciaTest",
            "decodeLeaf",
            (Token::Bytes(leaf.clone())),
        )
        .unwrap();

        println!("decodeLeaf: {:?}", &result);
    }
}

static D: &'static [u8; 3] = &[0x01u8, 0x23, 0x45];

#[test]
fn test_nibble_slice_ops_basics() {
    let mut runner = runner();

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "nibbleLen",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),),
    )
    .unwrap()
    .as_u32();

    assert_eq!(result, 6);

    let result = execute::<_, bool>(
        &mut runner,
        "MerklePatriciaTest",
        "isNibbleEmpty",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),),
    )
    .unwrap();

    assert!(!result);

    let result = execute::<_, bool>(
        &mut runner,
        "MerklePatriciaTest",
        "isNibbleEmpty",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::from(6))]),),
    )
    .unwrap();
    assert!(result);

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "nibbleLen",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::from(3))]),),
    )
    .unwrap()
    .as_u32();
    assert_eq!(result, 3);

    for i in 0..3 {
        let result = execute::<_, Uint>(
            &mut runner,
            "MerklePatriciaTest",
            "nibbleAt",
            (
                Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::from(3))]),
                Token::Uint(Uint::from(i)),
            ),
        )
        .unwrap()
        .as_usize();
        assert_eq!(result, i + 3);
    }
}

#[test]
fn test_nibble_slice_ops_mid() {
    let mut runner = runner();
    let nibble = execute::<_, Token>(
        &mut runner,
        "MerklePatriciaTest",
        "mid",
        (
            Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),
            Token::Uint(Uint::from(2)),
        ),
    )
    .unwrap();
    for i in 0..4 {
        let result = execute::<_, Uint>(
            &mut runner,
            "MerklePatriciaTest",
            "nibbleAt",
            (nibble.clone(), Token::Uint(Uint::from(i))),
        )
        .unwrap()
        .as_u32();
        assert_eq!(result, i as u32 + 2);
    }

    let nibble = execute::<_, Token>(
        &mut runner,
        "MerklePatriciaTest",
        "mid",
        (
            Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),
            Token::Uint(Uint::from(3)),
        ),
    )
    .unwrap();

    for i in 0..3 {
        let result = execute::<_, Uint>(
            &mut runner,
            "MerklePatriciaTest",
            "nibbleAt",
            (nibble.clone(), Token::Uint(Uint::from(i))),
        )
        .unwrap()
        .as_u32();
        assert_eq!(result, i as u32 + 3);
    }
}

#[test]
fn test_nibble_slice_ops_shared() {
    let mut runner = runner();
    let n = Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]);

    let other = &[0x01u8, 0x23, 0x01, 0x23, 0x45, 0x67];
    let m = Token::Tuple(vec![Token::Bytes(other.to_vec()), Token::Uint(Uint::zero())]);

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "commonPrefix",
        (n.clone(), m.clone()),
    )
    .unwrap();
    assert_eq!(result, Uint::from(4));

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "commonPrefix",
        (m.clone(), n.clone()),
    )
    .unwrap();
    assert_eq!(result, Uint::from(4));

    let m_mid_4 = execute::<_, Token>(
        &mut runner,
        "MerklePatriciaTest",
        "mid",
        (m.clone(), Token::Uint(Uint::from(4))),
    )
    .unwrap();

    let result = execute::<_, bool>(
        &mut runner,
        "MerklePatriciaTest",
        "startsWith",
        (m_mid_4.clone(), n.clone()),
    )
    .unwrap();

    assert!(result);

    let result = execute::<_, bool>(
        &mut runner,
        "MerklePatriciaTest",
        "startsWith",
        (n.clone(), m_mid_4.clone()),
    )
    .unwrap();

    assert!(!result);

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "commonPrefix",
        (n.clone(), m_mid_4.clone()),
    )
    .unwrap();

    assert_eq!(result, Uint::from(6));

    let n_mid_1 = execute::<_, Token>(
        &mut runner,
        "MerklePatriciaTest",
        "mid",
        (n.clone(), Token::Uint(Uint::from(1))),
    )
    .unwrap();

    let m_mid_1 = execute::<_, Token>(
        &mut runner,
        "MerklePatriciaTest",
        "mid",
        (m.clone(), Token::Uint(Uint::from(1))),
    )
    .unwrap();

    let m_mid_2 = execute::<_, Token>(
        &mut runner,
        "MerklePatriciaTest",
        "mid",
        (m.clone(), Token::Uint(Uint::from(2))),
    )
    .unwrap();

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "commonPrefix",
        (n_mid_1.clone(), m_mid_1.clone()),
    )
    .unwrap();

    assert_eq!(result, Uint::from(3));

    let result = execute::<_, Uint>(
        &mut runner,
        "MerklePatriciaTest",
        "commonPrefix",
        (n_mid_1.clone(), m_mid_2.clone()),
    )
    .unwrap();

    assert_eq!(result, Uint::from(0));
}

#[test]
fn test_merkle_patricia_trie() {
    let (root, proof, key) = proof_data();

    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyKeys",
        (
            Token::FixedBytes(root.to_vec()),
            Token::Array(proof.clone().into_iter().map(Token::Bytes).collect()),
            Token::Array(vec![Token::Bytes(key.to_vec())]),
        ),
    )
    .unwrap();

    let timestamp = <u64>::decode(&mut &result[0].1[..]).unwrap();
    assert_eq!(timestamp, 1_677_168_798_005)
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_transaction_trie_single_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("ecabc214ab6c55e1342e888fa677e2bcc29218a4b248a56fcebf7aa357807b60").to_vec()),
        Token::Array(vec![
            hex!("f89b822080b89601f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec()
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("80").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1,hex!("01f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec())
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_transaction_trie_multi_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("ac39df3a470f95659f9f6f30c4de252479ddd4e6083ba7a7be72d2505b4062e2").to_vec()),
        Token::Array(vec![
            hex!("f90131a0abd3b92264de818dd5c44b3212ee3d20de2478ca6a080d59b0f7eadc165aea33a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a06bae3f278b07352be6e823e9c9584d2a8ba01e000cc7653b5b1d213888b841548080808080808080").to_vec(),
            hex!("f871a036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da060c25b7b04d23c401c874963020e932bcafdef5b9b5c4f25394e2c3bba644feca06cf2dabf824eee4758b57a77612e1f7a0d483e3656d9a76ea7b11a70a50dd4008080808080808080808080808080").to_vec(),
            hex!("f8b1a0cb8fc8ea7d198bd1b6fb48a51e17932ad8333ef0b57b17326fbe3c4f6abf231ea018c89cbf38ef1aa86fc642cfc5eae17f49aef97c493c5ada614743d630de32fba018c89cbf38ef1aa86fc642cfc5eae17f49aef97c493c5ada614743d630de32fba018c89cbf38ef1aa86fc642cfc5eae17f49aef97c493c5ada614743d630de32fba0951955209df36420e52fc0961cba8318a288676262651f9e7cdafd0cf177c1e5808080808080808080808080").to_vec(),
            hex!("f90211a03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aaa03f4a0248cd0ff7ad4496f72fde07d31a0d46d7986af6505f0e4e85b72b3401aa80").to_vec(),
            hex!("f90211a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd1a014dd1fc275045e27cee26d6ec8395aa68681155e524550de255580f4181e7cd180").to_vec(),
            hex!("f90211a036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036da036218dd16b29d804118d9bb961896fd3eb036e028af02d3638937cdcaa65036d80").to_vec(),
            hex!("f89920b89601f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec()
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("8232c8").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1,hex!("01f89301808080808080f847f84580f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000080a08c7939f0e613736150a05565fcddda959b22c44ddac6c6aed8ec59e1462a0498a0166d30e3763829d64fca3d38601e65ba6f0e94f7e3c544381ae5e9e9b12dacd0").to_vec())
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_state_trie_single_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("0ce23f3c809de377b008a4a3ee94a0834aac8bec1f86e28ffe4fdb5a15b0c785").to_vec()),
        Token::Array(vec![
            hex!("f86aa1205380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab846f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec(),
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1, hex!("f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec())
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_state_trie_multi_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("4dc3e58e944d713c36c6b9cc58df023b3e578093de16e175faefa8f91727ca6e").to_vec()),
        Token::Array(vec![
            hex!("f90211a07466452b9c24acc76f0c9a0a4d43f5b362a031626eb6a0d7e7409c9c2fe1ecdda00bc98d4eaa34347ecb42d4d716161612692c2ac599cf3c4f5eade18fbb07da4ca00146ab246da36aec011dcdf8fd4c6a505ec7caca75441268c7eab80e9aa96767a038a41d42f1edccf59f2a1d6e7887ab1f3dfcd0a26f3be309ee237ed4aecd9d38a05f542a7ffff85163015c7cfc8c7d947ac98114f1bc576ab74ec663dd97d9596fa0208cb7384b248a341c22ef52d1882f6045345c6435c38a5b4d382e7a02c53f48a086b590086c7e7738c59cd0bba1a136dc42cc099fa9ae8af77abaa76fa1f3f503a0ab69ef5e7d461a547675de48c30be16f2d297509f6d005325365cbebe8735104a0896573c4595ea56992cb4237091ce8f00a73988f80506ef7bde78de9cfddbfa9a06d78ae475034b4aec9afef58c3f93e997f2c50f2a4948a7214b0295c5ae1776ea0763c0ec3ea13b7cbfe139cf8a3cf76e75026b2d42854bf822a47a0497dabf679a028fd50ebf9eed4e9a0969a73682ea615cb1134510f80aa057c60acf657a13a05a00c9f1e12244dabf2db619f0ce1098dd6d19f7c9dd1b17da1ffd02b0e0f3d4d7ea0aa2a772e989b23bd7e2eba714f153031c79c03cb835539fc56debc7669b64148a07f6544adbc5e30eca006a050384d85df7a510bac66dde8c32b7741486b319610a0c859cc09be23308083a16f96c19dffd9b48770b715c150220a35e07ff5ea716b80").to_vec(),
            hex!("f90171a02ffa31221e3db9f56751599b181b16cd0489d9870f58a481ee1398d6991a6ed3a0af7f7b8a8aa219ebd9e9562bd3f917c47f7205bb0f29bdb064c63e51f8e14ee680a0fc0482eb10e5eccc57013233746a95072c2d80746898c30a23fc43c52eabddf5a0985b92a5617ee65b05be517cbbeb1c5598e5479bdb45107552b80d339c6c23eba0984d7ace51d61b40d4336aec39c867fc5db4566036ef0e6225df604dd93a6538a068ff593d5fc203763242dc6b95e559472f8d43ceed1a4fececb11a0eb6ef1070a0d7a609f017d3641ff18327916212ebf21d6ae93b3ffe09ae6fc5e1160c7f571f80a0d62e9137db3e883d506c3927310d0100e624b5befe180830f029c99859451230a0ce9a78f4d5abb17cfe7c189a83524a479bd8aed870cc7608c3ede431cdd214cd8080a0f58d48fa8ca7b152aa825128a173c6061b6cabe9143473e246f6d8732f59cc3880a030a23d0cd92c346ce27019e17ddbf8651695cd3fd6350f0f7862f915269a57ff80").to_vec(),
            hex!("f8518080808080808080a0fed0c7841e83453b78135ca2a36e8fb5d8c5fbb5883746f3f93054e42205e7e880808080a0711f6aa6ad472844f3e563a1c3ff5777c4e2c3b3126b42fa4eb4d115546116c5808080").to_vec(),
            hex!("f8689f30c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312ab846f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1,hex!("f8448080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec())
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_receipt_trie_single_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("fe815f93891907b401edd491a8601cb732dabe909f0bf74aace83d997e02918f").to_vec()),
        Token::Array(vec![
            hex!("f901c0822080b901baf90107c1010180b9010000000000000000000081000000000000000000000000000000000002000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000040000080000000400000000000000000000000000000000000000000000000000000000000000000000010000010000000000000000000000000000000001400000000000000008000000000000000000000000000000000f79422341ae42d6dd7384bc8584e50419ea3ac75b83fa004491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f80f87694e7fb22dfef11920312e4989a3a2b81e2ebf05986b8407f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442fd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b69e2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b").to_vec(),
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("80").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1, hex!("f90107c1010180b9010000000000000000000081000000000000000000000000000000000002000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000040000080000000400000000000000000000000000000000000000000000000000000000000000000000010000010000000000000000000000000000000001400000000000000008000000000000000000000000000000000f79422341ae42d6dd7384bc8584e50419ea3ac75b83fa004491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f80f87694e7fb22dfef11920312e4989a3a2b81e2ebf05986b8407f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442fd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b69e2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b").to_vec());
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_receipt_trie_multi_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("f541c53ea23ba46707824e91aa5542d84eebefb3d52fc93f1716d60add548737").to_vec()),
        Token::Array(vec![
            hex!("f90131a0d7c990d4d3f5d994ec0f1420044863553575abf7a11a342322eca1098beed5b4a06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea06d817ad4a2ad468905a8ff32fc5d62df023b1253b6c0c3e56538539b2506a53ea073c8a66ddc77ed8e7737802ade457d3ccfa3a08677b9bb97c4530c0ee89879b98080808080808080").to_vec(),
            hex!("f901f180a0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bda0feaa2deb376f5abf31480face579ade790ca329a2d8fb6f2959096f07ba7d9bd80").to_vec(),
            hex!("f901be20b901baf90107c1010180b9010000000000000000000081000000000000000000000000000000000002000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000040000080000000400000000000000000000000000000000000000000000000000000000000000000000010000010000000000000000000000000000000001400000000000000008000000000000000000000000000000000f79422341ae42d6dd7384bc8584e50419ea3ac75b83fa004491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f80f87694e7fb22dfef11920312e4989a3a2b81e2ebf05986b8407f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442fd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b69e2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b").to_vec()
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("01").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1, hex!("f90107c1010180b9010000000000000000000081000000000000000000000000000000000002000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000040000080000000400000000000000000000000000000000000000000000000000000000000000000000010000010000000000000000000000000000000001400000000000000008000000000000000000000000000000000f79422341ae42d6dd7384bc8584e50419ea3ac75b83fa004491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f80f87694e7fb22dfef11920312e4989a3a2b81e2ebf05986b8407f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442fd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b69e2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b").to_vec());
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_storage_trie_single_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (
            Token::FixedBytes(
                hex!("b9d1a401293d84978870a16d07fb2687c2fe446f94302b9b89d1fdfcc17f720e").to_vec(),
            ),
            Token::Array(
                vec![hex!(
                    "e4a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5638180"
                )
                .to_vec()]
                .into_iter()
                .map(Token::Bytes)
                .collect(),
            ),
            Token::Array(vec![Token::Bytes(
                hex!("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563").to_vec(),
            )]),
        ),
    )
    .unwrap();
    assert_eq!(result[0].1, hex!("80").to_vec());
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_storage_trie_multi_node() {
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (Token::FixedBytes(hex!("ffb7f68eaf1ef5b5aa838621a8ae0f2317992672da7d572236895557be62dead").to_vec()),
        Token::Array(vec![
            hex!("f90211a0c63bc0f27d1bf083b52c9162b8390a5f2f3e0fd1fc3c68dc9b53f414dec4293aa05d0312b83f74fb3324d01ff2a56de4bded7486ecb004539709ea7bd40b8a7b5ea01563c02eb256f474f597b0aef92ae30d34c492dcba30580eca279fcd99ec6275a0437128e7cd04a4129f48222735c59e2c1a4035286e0e2892d117849d07657ad6a0e812dda3a599643c60b990f9dcc0259473e4b02ed4da5624f36a7bcd3583d84ba082d7b25fd52ef540173638c22cf30cabfb1ca8880533a41a7ba9616e23ae5e30a085afed9de3cdcd64ca16dac64eb60a0a49d7926b9de0df7d135b0ef9299aa2e7a07d1f8cbfdd80fdb8e734139e7cff500002ce3ea04f8e7e7a65f7ee76373ba052a082d333caa80beb65d520d7eada9f48382c951ed201c4db6e234ed4bfd741831aa0fecf3839dca4fb2074056d45d8654446fc0bc35dd729c057ce47f624da1406c3a0a220dbb9b1afa52e1c8356134f72d79e78119882bc4ae82b0c9eb09e8237f73ba0430d634294001ad8bbf7e9e8934ed53fac9c1dd58b318e868161e549b96fbdcaa0d139a88a1fc490c42445c4c3fb7056cccccc9fb422221ccee614d6a8c3283ae9a0f327ef1cd0da3765c2218466667775b858fe170f7699063ebb386f615b581fc7a0504fddf4ea09a2f3be60c9783dc4d4b1f759c9ffa1083189442b904576b69576a0a646afb9b8836e8dab290064e553af0f6bd42c038791aee602197b26d2dbf87580").to_vec(),
            hex!("f90111a07389d98c79eb4836dabcb6bd3a7791d450c706c7556040cdd3988e5367857466a08dc351c579002352b5c36aa489ec19cce91825a5463ad956756fa3f74856c27d808080a0fbbe85f885abfae725bccc4a6c2f7cb9028271cfc48eb51c78a32c2ef8a58ddaa071fe8e3fb4bf1025153ecca0478fddbf8d791bc1de5f54fab5d5f906d1d2a6e8808080a01e0a980530f5be28de03db7cb8d973e70098c0ecbb05bc653f3482a49f50dcd58080a067c53bc2ed22d7afbc86921e0a7fdc2467ae93e0ce1dbc8353df46e9c128fc8ba0a3038946f9746409bb3c437ceb86c3933fd311fe1a81b7d89b91ac51065634d5a07f9f281b145be5d9a0854f1fc3c0720566aca0c5585d0024cd1128895ae00d3980").to_vec(),
            hex!("f85180a0449562ac8ce77c19644bb844d2162ae4f7426d156232af2cf5c7bebf985ccff18080a03a24d1a9a95ff6d53aeb3a6771cb596208ab47c33045ea2015d68b4a9e1a8445808080808080808080808080").to_vec(),
            hex!("e59f3540171b6c0c960b71a7020d9f60077f6af931a8bbf590da0223dacf75c7af84830dbba0").to_vec()
          ].into_iter().map(Token::Bytes).collect()),
        Token::Array(vec![Token::Bytes(hex!("6e1540171b6c0c960b71a7020d9f60077f6af931a8bbf590da0223dacf75c7af").to_vec())]),),
    )
    .unwrap();
    assert_eq!(result[0].1, hex!("830dbba0").to_vec());
}

#[test]
fn test_merkle_patricia_trie_ethereum_verify_storage_trie() {
    //from ethereum-triedb repository
    let key = hex!("3483bb4c3738deb88e49108e7a5bd83c14ad65b5ba598e2932551dc9b9ad1879").to_vec();
    let proof = vec![
        hex!("f90211a021162657aa1e0af5eef47130ffc3362cb675ebbccfc99ee38ef9196144623507a073dec98f4943e2ab00f5751c23db67b65009bb3cb178d33f5aa93f0c08d583dda0d85b4e33773aaab742db880f8b64ea71f348c6eccb0a56854571bbd3db267f24a0bdcca489de03a49f109c1a2e7d3bd4e644d72de38b7b26dca2f8d3f112110c6fa05c7e8fdff6de07c4cb9ca6bea487a6e5be04af538c25480ce30761901b17e4bfa0d9891f4870e745509cfe17a31568f870b367a36329c892f1b2a37bf59e547183a0af08f747d2ea66efa5bcd03729a95f56297ef9b1e8533ac0d3c7546ebefd2418a0a107595919d4b102afaa0d9b91d9f554f83f0ad61a1e04487e5091543eb81db8a0a0725da6da3b62f88fc573a3fd0dd9dea9cba1750786021da836fd95b7295636a0fd7a768700af3caadaf52a08a23ab0b71ca52830f2b88b1a6b23a52f9ee05507a059434ae837706d7d317e4f7d03cd91f94ed0465fa8b99eaf18ca363bb318c7b3a09e9b831a5f59b781efd5dae8bea30bfd81b9fd5ea231d6b7e82da495c95dd35da0e72d02a01ed9bc928d94cad59ae0695f45120b7fbdbce43a2239a7e5bc81f731a0184bfb9a4051cbaa79917183d004c8d574d7ed5becaf9614c650ed40e8d123d9a0fa4797dc4a35af07f1cd6955318e3ff59578d4df32fd2174ed35f6c4db3471f9a0fec098d1fee8e975b5e78e19003699cf7cd746f47d03692d8e11c5fd58ba92a680").to_vec(),
        hex!("f90211a07fc5351578eb6ab7618a31e18c87b2b8b2703c682f2d4c1d01aaa8b53343036ea0e8871ae1828c54b9c9bbf7530890a2fe4e160fb62f72c740c7e79a756e07dbf3a04dd116a7d37146cd0ec730172fa97e84b1f13e687d56118e2d666a02a31a629fa08949d66b81ba98e5ca453ba1faf95c8476873d4c32ff6c9a2558b772c51c5768a028db2de6d80f3a06861d3acc082e3a6bb4a6948980a8e5527bd354a2da037779a09b01ba0fe0193c511161448c602bb9fff88b87ab0ded3255606a15f8bca9d348a0c1c1c6a89f2fdbee0840ff309b5cecd9764b5b5815b385576e75e235d1f04656a04e827215bb9511b3a288e33bb418132940a4d42d589b8db0f796ec917e8f9373a099398993d1d6fdd15d6082be370e4d2cc5d9870923d22770aaec9418f4b675d7a00cd1db5e131341b472af1bdf9a1bf1f1ca82bc5b280c8a50a20bcfff1ab0bdd4a09bbcc86c94be1aabf5c5ceced29f462f59103aa6dafe0fc60172bb2c549a8dbaa0902df0ba9eed7e8a6ebff2d06de8bcec5785bb98cba7606f7f40648408157ef4a0ba9dfd07c453e54504d41b7a44ea42e8220767d1e2a0e6e91ae8d5677ac70e50a0f02f2a5e26d7848f0e5a07de68cbbbd24253d545afb74aac81b35a70b6323f1ca0218b955deca7177f8f58c2da188611b333e5c7ef9212000f64ca92cd5bb6e5a0a049cd750f59e2d6f411d7b611b21b17c8eefe637ca01e1566c53f412308b34c6280").to_vec(),
        hex!("f90211a05303302919681c3ad0a56c607c9530ed910f44515f6b40c9633d1900bbbc7e0fa0459fc49e57f39ca6471b1c6905ede7eaa6d7186c8249485cc28338ba18c540cba0825307726d1b7c9d74973d37c12e8b035bf0334836e48ec3f2ff18bf2232dabea0a67ef68daba820c7d6343d1b147b73430ce5c5915a27581cfd12946c2307dc49a003c9b0f0b784de7d72f3b5d5fea87e30dc5fc6f93a0c218240f79a2c74b0f8e2a05a38ddf70df168305b8ba38e8ee54dfadc3f7d81335ec849cb143a10d9738a91a058f0692b5cb07a1c8c800fcf8a70c6e6189a5d72f24ca0040423cf450df1da44a0890dbc62e7429fcca3f1507ad2cd4799c0a7aab25db37ccad434ae23ae889807a075be60d2f635292e69dbc600600605cb8eaf75e96425fd3f2347a5c644db43b9a07b65ba06ee9d2b5dab0a9acc1b8b521cb42f91566de9c174636e817c3d990265a0de65bc6092e28b0cc1ed454fcc07ce26df21bb05efe0a4b4472ff63278e28b95a08077cd7de83428d376ff7588b32df903d2764af7d41deb9c873e9ae889823cd3a0af2f63837dc01e2efb9e40815761015a0d740c2d2549593eefd291a05d40b55aa0c3214baa8d347bd5703926b6fe3ee2f607d0debc0fd73352696dc10f4cbc517da01756cf85b4785bda4a9867a453f8ca1948f015bd329b84083f14d313bddafb80a00dac89194bc1f28d3971b9ca9d1e16a49c6383557187d7bbeb899626d60bfb1980").to_vec(),
        hex!("f90211a0bf50b49fae6cfe8b7671e3fa0c163aed76f6457720a2b7c18f567b3c02194c29a070dc71bb7e399e5ae66958261108c84b75e8aacc8d255ce28cd7c9029358872ba0d2ae86d376e65eee52338ad4a1951deb9312f2c161fdf5cfc3e36d5a07ee4239a0f2029dea5033d0e788191ba25fc25bb0570bdbbaf321dfdb076f6695c649a07ca066074b59980560ecdd8ebc96eeb93f50dc1e92983659ea4a6a61a4cff0f474cba01ad85159ddc98609ea628cd17897fe08b0d9a7bb07a2087d92a673e063039aaba04921580f8766f8f156546abd8f0e44af250b34e7323f35c40fdc078223822344a034e07b24a1c17f5dcff27b766099c206fbbb6e549d3f4c02fd8db0241061482aa0c852267182c35e2e5014ab6d656672e9446aaf79c6248d103870d55ee36368b1a00aed203f7e2684942a64f05306e57d64fd44eded94e2ce95e462be93adff640da02cea88d74264c91c546de3822b6169a427559781a774511409864d70a834706ea01d542f8a9b69674e58a5bb89fafb5e79cbe3607732455b09c2a996df48e48837a04c3bbb4f47041018455347567a4e3af472fafe179871f667c3d26038f5dabacfa03c4f12f7cdd35126ce5452aa8322bc8b497eb06c5c41741b590d40645a8fd14ea01334e9a4160b44b622e9523cb587d8ba4795bbf9ad3dd0aa1a2b7f5c6a5cbe94a08feae3d50602063d65763185633aa6e23bb47eca9a39982a4863a7cc6d3586ff80").to_vec(),
        hex!("f90211a03fc22103871f30d114942583d24adfab1ce2e651ff6705a05964318fde7c425aa01c86fd2e9d2a823db33bf4089ce1af41332b4e3069b31bb70a67861944d71688a08a90ae88b4479d21135517195f50df20fc29dbe495e09440b0fa5797fc0352c8a02a195c4a89ab6322d8daa221124274d711a9435587406addfb289f9360c0b1caa02f7ed0113a1b72febc7ceb7d9193baeaa093aebea76eea4729821f53d29b302ea07d5cbbeffd22fb0f9d510576cac47a604b2121ef8b08588eaefc46a07844515ca01c0c09d203e342fab9f80835f3aa7bb7e94cbf94d3a18b21ce905e75b690673fa07c310f931f12d1651dbb9bdffbe5e0a16db981dccfb3f4a838592e2347b1b187a091b24e00d37034ed70e0c6653f8616363efbea43be86d52aabf6a9c5d5049d3aa017cc8ab2e63508691dee64ddb2dbe5352fe531f55728368cab3d8634450730dca0d8ee92d688eabcdf28af1830d7217fcd1431c0b0e3311039c422c5f45f9d525da0abe4323ef90fb783ffd6bf29d240818b0a2477d2ad4577fce57642a5ba476957a0eee3fbc510b1a6d8da176b9eab2035837769988b216fcef67f6a215e5e261d5ea082bc27591d8b0408739712c2f0e623e3d296d12afd6b7356dae237a315a6ce3ba0634affb8f9744fed774851772cb5ce495c50212961a64262d915632c2bede721a0345017d846f3be29dca1f56a734886c26cb49d3bcbbae5f7356e55e71d84147d80").to_vec(),
        hex!("f90211a0a152d08043b3865248d8ae9c4594d6e09079f61ee4ad9afca98d3befb3a9307ca01313ea4df7ec991f5ba1b2175408765ea67111857ae25cafe21986810d633353a05cb00f30a4b6749cb8d01dda2ad665a2c570b7c6959b364c46da75fc2aebfa14a0a493d42fa40d6c8fb23090f20cebe9f1cde8a47d9594e666096c3f76219cfb34a06d2149e05ba1a31bcc352fd3a79fd42d95383f14a312862fa5f4b7b7bdb63254a0f40094679bf0599fdeecae8c800a423ad2499b67f9546d4085d5b7a351561072a05036fc625ed5a13d143fd0984e99969d2d48f962baec80b3f0e78323c8e864ffa0c0887db54ab0d4309ed5f563448bfc78a4a88c3a5473fcbd9bd263c8fcca4b9fa04287b193a315cba13a49482b4d83c068cf08b622593111e416b7a3b815e3595aa051b82224b54dc4050703157cdd6c74c618872c798badce7192fe1fd534814d5da017ac02273956b25dc2429750156e0a45bf461437bec84b784d19a5b964dd6882a05be9c25f80a6f34e9eb526d6c3c89e3ec2c5dd769d2d915d835208cac3f56d36a0ea7ae8e74baeae9d6307371f85cce46ba7ad46b5c2b3616a3573a26e1260bc31a04446678b6bf75075ae0261c179d88e49fae1d9482c214ec8c693239b583a6b18a09ec91d47f671c343cea224def0afcd62a57a408ac0e36b79cf29a4495ff9055ca0c3da71d14030daf8fb9157ec84f077df97dff395c1fcf8f04361e02aa1af36ff80").to_vec(),
        hex!("f8b1808080a038f5e1b2680d95eaf7f225b996fc482f60cabcebeae26f883a4b58e1e9c7bbeda0c220c5d76d85ad38d8f82d0d6d6f48db3c23ae3657d1ac3ca6e2d98b4e48bfde8080a06fe32c7c1f8f80ebe5128f11a7af3a5bc47dbc6ac0af705069532b1cbefd6792a0015eb7d24835c910fc5f906627968a1a9e810cb164afd634ca683b6bb34f0241808080808080a03ca1d0ead152d38c16bda91dac49e3f0c9a0afeaa67598c1fce2506f5f03162680").to_vec(),
        hex!("f86d9d3c3738deb88e49108e7a5bd83c14ad65b5ba598e2932551dc9b9ad1879b84df84b10874ef05b2fe9d8c8a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec(),
    ];
    let root = hex!("024c056bc5db60d71c7908c5fad6050646bd70fd772ff222702d577e2af2e56b").to_vec();
    let mut runner = runner();

    let result = execute::<_, Vec<(Vec<u8>, Vec<u8>)>>(
        &mut runner,
        "MerklePatriciaTest",
        "VerifyEthereum",
        (
            Token::FixedBytes(root),
            Token::Array(proof.into_iter().map(Token::Bytes).collect()),
            Token::Array(vec![Token::Bytes(key)]),
        ),
    )
    .unwrap();
    assert_eq!(
        result[0].1,
        hex!("f84b10874ef05b2fe9d8c8a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec()
    );
}
