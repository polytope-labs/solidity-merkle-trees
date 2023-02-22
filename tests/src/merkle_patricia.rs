use crate::forge::{execute, runner};
use codec::{Compact, Decode};
use ethers::abi::{Token, Uint};
use hex_literal::hex;
use sp_core::Blake2Hasher;
use sp_trie::{LayoutV0, NodeCodec};
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

fn to_tokens(kind: NodeKind) -> Token {
    Token::Tuple(vec![
        Token::Bool(kind.0),
        Token::Bool(kind.1),
        Token::Bool(kind.2),
        Token::Bool(kind.3),
        Token::Bool(kind.4),
        Token::Bool(kind.5),
        Token::Bool(kind.6),
        Token::Bool(kind.7),
        Token::Uint(kind.8),
        Token::Tuple(vec![
            Token::Bytes(kind.9.0),
            Token::Uint(kind.9.1),
        ])
    ])
}

#[test]
fn test_merkle_patricia_trie() {
    let key = &hex!("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb");
    let proof = vec![
        hex!("80650080ec49ce7a8c84f2c71ce779603a0f2e17bd5dd924dfd75ababe4d168edd8b450580c19634a0984ac6bdad5352ce0acd291248b3dffddc970d50c03df34991cdec2f80c0790cef8e3690dddeded75a26f8edc6779ba73159ac4abaf5496157c335b485801d8c6bd56b9fbc94a728b0a2426bcb15979b1dff2dd66515d152a91124ea933f").to_vec(),
        hex!("80ffff807106ca9760e795f38916653567345059ad742c31ab69aeca1c860aea7102193780a7305000700aa4c2aac95f267d5bf9a24fb1ca6b468484936f10fd2ed94c19fc80ff5d0778287b9a40112e33b5e34bb4430550cfe26ee316af2b879faf73f23a6b809c17b52fc2534ef284344420eb22e2ca88dcb4d92a065eb75ae52d238886cdc580ef724e77b9860879accd23eba13d792927dc8194eccf20552c30e7a2beb677d38076d8da83c0f4245a62e93c7579502dd0f81eed86909511a7eed6bb3b6e71282280e1a90991484e3d9586cbe8d81b375306f9a62b9d773d1c2e5ec78c38b30f96ad809dd632fc09227e2ed4ce24b6f442cdc9ba5f728d2c8fb6025e5193738e5dc9ed80e1eb260a55fafa8b43894c5213e635f3cf0f4cea94919733b81b0da55d351bb080cf7b4954f9630de7a63bb97038b331a6fb628d5d8039ea9e0f81cc13e33eaf27805f53a49ff1d69a4cc6426fda574dc275465016e4c6b10bec145e282068fc4740805dfa4a5311622a84a806665f6547225b92dde897f634ca457354ef111e01c2a380907e07f055a2127a67097534b1a3e83a44949edf090a6e1d1ce44093a8afd60d804c4f2d20e35112ac4b75d811dcae8505e1ea87ca0192f2e9c6ded19bf3279bbb80dd3d48c827adefd94cc4ab6c3e6fa232bff5007ffb27d0200d6ee141147029368033aabc0ee41c738646b36b9314f8896faa4628dc29e99777dacc9cf59b88599a").to_vec(),
        hex!("9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20f0d6907a86010000").to_vec(),
    ];

    let root = hex!("6bc3bb2fe38fc4d08ef21f61bd9a9f9d70c4a5f957448ac65786d56a1e1cd5f0");

    let mut runner = runner();

    for item in proof.clone() {
        let result = execute::<_, NodeKind>(
            &mut runner,
            "MerkleTests",
            "decodeNodeKind",
            (Token::Bytes(item.clone())),
        );

        println!("decodeNodeKind: {:?}", &result);

        let result = execute::<_, Token>(
            &mut runner,
            "MerkleTests",
            "decodeNibbledBranch",
            (Token::Bytes(item.clone())),
        );

        println!("decodeNibbledBranch: {:?}", &result);

        let plan = NodeCodec::<Blake2Hasher>::decode_plan(&mut &item[..])
            .unwrap()
            .build(&item)
            .to_owned_node::<LayoutV0<Blake2Hasher>>()
            .unwrap();

        println!("{:#?}", plan);

        println!("\n\n\n");
    }

    let result = execute::<_, Vec<Vec<u8>>>(
        &mut runner,
        "MerkleTests",
        "testMerklePatricia",
        (
            Token::FixedBytes(root.to_vec()),
            Token::Array(proof.clone().into_iter().map(Token::Bytes).collect()),
            Token::Array(vec![Token::Bytes(key.to_vec())])
        ),
    );

    println!("{}", Compact::<u64>::decode(&mut &result[0][..]).unwrap().0);
}
