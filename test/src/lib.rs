pub mod helpers;

#[cfg(test)]
mod tests {
    use crate::helpers::{execute, runner};
    use ethers::{abi::Token, types::U256};
    use hex_literal::hex;

    #[test]
    fn test_solidity() {
        let _root = hex!("72b0acd7c302a84f1f6b6cefe0ba7194b7398afb440e1b44a9dbbe270394ca53");
        let proof = vec![
            vec![
                (0, hex!("1a8da6deeedf22a65b8a552ec76a1f7ef67907c1f41c9279981423911e1bb742")),
                (1, hex!("00540198a1ef6f4ee4b6938be5cacf3b33d8988ee8d5f90044e6932b451e30b0")),
                (2, hex!("eabb03c592af442325d97bf94bd10f1054895a02b741086eab60b02037e67bd7")),
                (3, hex!("fdc99e493de3ae376733f5d181fa7b8b18c1dfc6503119597f40215217289e8e")),
                (4, hex!("aa856382eb8954abe5409552dee37ab9177a00413ae34b6cf82988ce8d5a48d2")),
                (5, hex!("5ad899e759ebee07febeff98964d18621638458fbf6a95c17252c4c0a3d2cfe5")),
                (8, hex!("2d858e75ddaf4da28de6af3d4d4393d9018e2bf8dc8d79de7aa200b27b1c25ea")),
                (9, hex!("736ad2a3e8190028a3a89933f92ea7bb0fc2616f3972a64380a2513c8e0d5e43")),
            ],
            vec![
                (3, hex!("e93e19056274e1c32599c86abfdee9354b20ed6d303df150cd49864ae85fd29a")),
                (5, hex!("0962f26a7a55770de9b5b7477317cd8f0dd28cbc4e793792c8f0d93ef0029aa1")),
            ],
            vec![(3, hex!("62f3ed9d0b006fae872c2fe620202be7e16b741232c9b7641a134915a79fa64e"))],
            vec![],
            vec![(1, hex!("303b91179fa7f87a1d8381670a67ccab7c0a5e7d6797bbb8270efb8759b5876c"))],
            vec![(1, hex!("48459896facce34edda5a7bbc502c1436a7b21bb6eafd4e234b938e7d8d814a2"))],
            vec![(1, hex!("20d34143d0be76f1271beac3039a896a97fa4aacc7d36dc6942ec9735cc18873"))],
            vec![(1, hex!("5ab43b8b43d9cac8d1bfeddb9d622f56027ada027d19f53224cc35e993e65240"))],
            vec![],
        ];

        let args = proof
            .into_iter()
            .map(|layers| {
                let layers = layers
                    .into_iter()
                    .map(|(index, node)| {
                        Token::Tuple(vec![
                            Token::Uint(U256::from(index)),
                            Token::FixedBytes(node.to_vec()),
                        ])
                    })
                    .collect::<Vec<_>>();
                Token::Array(layers)
            })
            .collect::<Vec<_>>();

        let mut runner = runner();

        execute::<_, Token>(&mut runner, "MerkleMultiProofTest", "calculateRoot", (args));
    }
}
