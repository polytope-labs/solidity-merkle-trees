#![allow(dead_code)]

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
            "MerkleTests",
            "decodeNodeKind",
            (Token::Bytes(item.clone())),
        );

        assert!(result.5); // isNibbledBranch

        let result = execute::<_, Token>(
            &mut runner,
            "MerkleTests",
            "decodeNibbledBranch",
            (Token::Bytes(item.clone())),
        );

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
            "MerkleTests",
            "decodeNodeKind",
            (Token::Bytes(leaf.clone())),
        );

        assert!(result.1); // isLeaf

        let result = execute::<_, Token>(
            &mut runner,
            "MerkleTests",
            "decodeLeaf",
            (Token::Bytes(leaf.clone())),
        );

        println!("decodeLeaf: {:?}", &result);
    }
}

static D: &'static [u8; 3] = &[0x01u8, 0x23, 0x45];

#[test]
fn test_nibble_slice_ops_basics() {
    let mut runner = runner();

    let result = execute::<_, Uint>(
        &mut runner,
        "MerkleTests",
        "nibbleLen",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),),
    )
    .as_u32();

    assert_eq!(result, 6);

    let result = execute::<_, bool>(
        &mut runner,
        "MerkleTests",
        "isNibbleEmpty",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),),
    );

    assert!(!result);

    let result = execute::<_, bool>(
        &mut runner,
        "MerkleTests",
        "isNibbleEmpty",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::from(6))]),),
    );
    assert!(result);

    let result = execute::<_, Uint>(
        &mut runner,
        "MerkleTests",
        "nibbleLen",
        (Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::from(3))]),),
    )
    .as_u32();
    assert_eq!(result, 3);

    for i in 0..3 {
        let result = execute::<_, Uint>(
            &mut runner,
            "MerkleTests",
            "nibbleAt",
            (
                Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::from(3))]),
                Token::Uint(Uint::from(i)),
            ),
        )
        .as_usize();
        assert_eq!(result, i + 3);
    }
}

#[test]
fn test_nibble_slice_ops_mid() {
    let mut runner = runner();
    let nibble = execute::<_, Token>(
        &mut runner,
        "MerkleTests",
        "mid",
        (
            Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),
            Token::Uint(Uint::from(2)),
        ),
    );
    for i in 0..4 {
        let result = execute::<_, Uint>(
            &mut runner,
            "MerkleTests",
            "nibbleAt",
            (nibble.clone(), Token::Uint(Uint::from(i))),
        )
        .as_u32();
        assert_eq!(result, i as u32 + 2);
    }

    let nibble = execute::<_, Token>(
        &mut runner,
        "MerkleTests",
        "mid",
        (
            Token::Tuple(vec![Token::Bytes(D.to_vec()), Token::Uint(Uint::zero())]),
            Token::Uint(Uint::from(3)),
        ),
    );

    for i in 0..3 {
        let result = execute::<_, Uint>(
            &mut runner,
            "MerkleTests",
            "nibbleAt",
            (nibble.clone(), Token::Uint(Uint::from(i))),
        )
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

    let result =
        execute::<_, Uint>(&mut runner, "MerkleTests", "commonPrefix", (n.clone(), m.clone()));
    assert_eq!(result, Uint::from(4));

    let result =
        execute::<_, Uint>(&mut runner, "MerkleTests", "commonPrefix", (m.clone(), n.clone()));
    assert_eq!(result, Uint::from(4));

    let m_mid_4 = execute::<_, Token>(
        &mut runner,
        "MerkleTests",
        "mid",
        (m.clone(), Token::Uint(Uint::from(4))),
    );

    let result =
        execute::<_, bool>(&mut runner, "MerkleTests", "startsWith", (m_mid_4.clone(), n.clone()));

    assert!(result);

    let result =
        execute::<_, bool>(&mut runner, "MerkleTests", "startsWith", (n.clone(), m_mid_4.clone()));

    assert!(!result);

    let result = execute::<_, Uint>(
        &mut runner,
        "MerkleTests",
        "commonPrefix",
        (n.clone(), m_mid_4.clone()),
    );

    assert_eq!(result, Uint::from(6));

    let n_mid_1 = execute::<_, Token>(
        &mut runner,
        "MerkleTests",
        "mid",
        (n.clone(), Token::Uint(Uint::from(1))),
    );

    let m_mid_1 = execute::<_, Token>(
        &mut runner,
        "MerkleTests",
        "mid",
        (m.clone(), Token::Uint(Uint::from(1))),
    );

    let m_mid_2 = execute::<_, Token>(
        &mut runner,
        "MerkleTests",
        "mid",
        (m.clone(), Token::Uint(Uint::from(2))),
    );

    let result = execute::<_, Uint>(
        &mut runner,
        "MerkleTests",
        "commonPrefix",
        (n_mid_1.clone(), m_mid_1.clone()),
    );

    assert_eq!(result, Uint::from(3));

    let result = execute::<_, Uint>(
        &mut runner,
        "MerkleTests",
        "commonPrefix",
        (n_mid_1.clone(), m_mid_2.clone()),
    );

    assert_eq!(result, Uint::from(0));
}

#[test]
fn test_merkle_patricia_trie() {
    let (root, proof, key) = proof_data();

    let mut runner = runner();

    let result = execute::<_, Vec<Vec<u8>>>(
        &mut runner,
        "MerkleTests",
        "VerifyKeys",
        (
            Token::FixedBytes(root.to_vec()),
            Token::Array(proof.clone().into_iter().map(Token::Bytes).collect()),
            Token::Array(vec![Token::Bytes(key.to_vec())]),
        ),
    );

    let timestamp = <u64>::decode(&mut &result[0][..]).unwrap();
    assert_eq!(timestamp, 1_677_168_798_005)
}
