#![allow(unused_parens, unused_imports)]

mod forge;
mod merkle_patricia;

pub use crate::forge::{execute, runner};
use ckb_merkle_mountain_range::{
    helper::{get_peaks, pos_height_in_tree},
    mmr_position_to_k_index,
    util::MemStore,
    Error, Merge, MMR,
};
pub use ethers::{abi::Token, types::U256, utils::keccak256};
use hex_literal::hex;
use rs_merkle::{Hasher, MerkleTree};

#[derive(Clone)]
struct Keccak256;

impl Hasher for Keccak256 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        keccak256(data)
    }
}

struct MergeKeccak;

impl Merge for MergeKeccak {
    type Item = NumberHash;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Result<Self::Item, Error> {
        let mut concat = vec![];
        concat.extend(&lhs.0);
        concat.extend(&rhs.0);
        let hash = keccak256(&concat);
        Ok(NumberHash(hash.to_vec().into()))
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Default)]
struct NumberHash(pub Vec<u8>);

impl From<u32> for NumberHash {
    fn from(num: u32) -> Self {
        let hash = keccak256(&num.to_le_bytes());
        NumberHash(hash.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type MmrLeaf = (u64, u64, [u8; 32]);

    #[test]
    fn multi_merkle_proof() {
        let leaf_hashes = [
            hex!("9aF1Ca5941148eB6A3e9b9C741b69738292C533f"),
            hex!("DD6ca953fddA25c496165D9040F7F77f75B75002"),
            hex!("60e9C47B64Bc1C7C906E891255EaEC19123E7F42"),
            hex!("fa4859480Aa6D899858DE54334d2911E01C070df"),
            hex!("19B9b128470584F7209eEf65B69F3624549Abe6d"),
            hex!("C436aC1f261802C4494504A11fc2926C726cB83b"),
            hex!("c304C8C2c12522F78aD1E28dD86b9947D7744bd0"),
            hex!("Da0C2Cba6e832E55dE89cF4033affc90CC147352"),
            hex!("f850Fd22c96e3501Aad4CDCBf38E4AEC95622411"),
            hex!("684918D4387CEb5E7eda969042f036E226E50642"),
            hex!("963F0A1bFbb6813C0AC88FcDe6ceB96EA634A595"),
            hex!("39B38ad74b8bCc5CE564f7a27Ac19037A95B6099"),
            hex!("C2Dec7Fdd1fef3ee95aD88EC8F3Cd5bd4065f3C7"),
            hex!("9E311f05c2b6A43C2CCF16fB2209491BaBc2ec01"),
            hex!("927607C30eCE4Ef274e250d0bf414d4a210b16f0"),
            hex!("98882bcf85E1E2DFF780D0eB360678C1cf443266"),
            hex!("FBb50191cd0662049E7C4EE32830a4Cc9B353047"),
            hex!("963854fc2C358c48C3F9F0A598B9572c581B8DEF"),
            hex!("F9D7Bc222cF6e3e07bF66711e6f409E51aB75292"),
            hex!("F2E3fd32D063F8bBAcB9e6Ea8101C2edd899AFe6"),
            hex!("407a5b9047B76E8668570120A96d580589fd1325"),
            hex!("EAD9726FAFB900A07dAd24a43AE941d2eFDD6E97"),
            hex!("42f5C8D9384034A9030313B51125C32a526b6ee8"),
            hex!("158fD2529Bc4116570Eb7C80CC76FEf33ad5eD95"),
            hex!("0A436EE2E4dEF3383Cf4546d4278326Ccc82514E"),
            hex!("34229A215db8FeaC93Caf8B5B255e3c6eA51d855"),
            hex!("Eb3B7CF8B1840242CB98A732BA464a17D00b5dDF"),
            hex!("2079692bf9ab2d6dc7D79BBDdEE71611E9aA3B72"),
            hex!("46e2A67e5d450e2Cf7317779f8274a2a630f3C9B"),
            hex!("A7Ece4A5390DAB18D08201aE18800375caD78aab"),
            hex!("15E1c0D24D62057Bf082Cb2253dA11Ef0d469570"),
            hex!("ADDEF4C9b5687Eb1F7E55F2251916200A3598878"),
            hex!("e0B16Fb96F936035db2b5A68EB37D470fED2f013"),
            hex!("0c9A84993feaa779ae21E39F9793d09e6b69B62D"),
            hex!("3bc4D5148906F70F0A7D1e2756572655fd8b7B34"),
            hex!("Ff4675C26903D5319795cbd3a44b109E7DDD9fDe"),
            hex!("Cec4450569A8945C6D2Aba0045e4339030128a92"),
            hex!("85f0584B10950E421A32F471635b424063FD8405"),
            hex!("b38bEe7Bdc0bC43c096e206EFdFEad63869929E3"),
            hex!("c9609466274Fef19D0e58E1Ee3b321D5C141067E"),
            hex!("a08EA868cF75268E7401021E9f945BAe73872ecc"),
            hex!("67C9Cb1A29E964Fe87Ff669735cf7eb87f6868fE"),
            hex!("1B6BEF636aFcdd6085cD4455BbcC93796A12F6E2"),
            hex!("46B37b243E09540b55cF91C333188e7D5FD786dD"),
            hex!("8E719E272f62Fa97da93CF9C941F5e53AA09e44a"),
            hex!("a511B7E7DB9cb24AD5c89fBb6032C7a9c2EfA0a5"),
            hex!("4D11FDcAeD335d839132AD450B02af974A3A66f8"),
            hex!("B8cf790a5090E709B4619E1F335317114294E17E"),
            hex!("7f0f57eA064A83210Cafd3a536866ffD2C5eDCB3"),
            hex!("C03C848A4521356EF800e399D889e9c2A25D1f9E"),
            hex!("C6b03DF05cb686D933DD31fCa5A993bF823dc4FE"),
            hex!("58611696b6a8102cf95A32c25612E4cEF32b910F"),
            hex!("2ed4bC7197AEF13560F6771D930Bf907772DE3CE"),
            hex!("3C5E58f334306be029B0e47e119b8977B2639eb4"),
            hex!("288646a1a4FeeC560B349d210263c609aDF649a6"),
            hex!("b4F4981E0d027Dc2B3c86afA0D0fC03d317e83C0"),
            hex!("aAE4A87F8058feDA3971f9DEd639Ec9189aA2500"),
            hex!("355069DA35E598913d8736E5B8340527099960b8"),
            hex!("3cf5A0F274cd243C0A186d9fCBdADad089821B93"),
            hex!("ca55155dCc4591538A8A0ca322a56EB0E4aD03C4"),
            hex!("E824D0268366ec5C4F23652b8eD70D552B1F2b8B"),
            hex!("84C3e9B25AE8a9b39FF5E331F9A597F2DCf27Ca9"),
            hex!("cA0018e278751De10d26539915d9c7E7503432FE"),
            hex!("f13077dE6191D6c1509ac7E088b8BE7Fe656c28b"),
            hex!("7a6bcA1ec9Db506e47ac6FD86D001c2aBc59C531"),
            hex!("eA7f9A2A9dd6Ba9bc93ca615C3Ddf26973146911"),
            hex!("8D0d8577e16F8731d4F8712BAbFa97aF4c453458"),
            hex!("B7a7855629dF104246997e9ACa0E6510df75d0ea"),
            hex!("5C1009BDC70b0C8Ab2e5a53931672ab448C17c89"),
            hex!("40B47D1AfefEF5eF41e0789F0285DE7b1C31631C"),
            hex!("5086933d549cEcEB20652CE00973703CF10Da373"),
            hex!("eb364f6FE356882F92ae9314fa96116Cf65F47d8"),
            hex!("dC4D31516A416cEf533C01a92D9a04bbdb85EE67"),
            hex!("9b36E086E5A274332AFd3D8509e12ca5F6af918d"),
            hex!("BC26394fF36e1673aE0608ce91A53B9768aD0D76"),
            hex!("81B5AB400be9e563fA476c100BE898C09966426c"),
            hex!("9d93C8ae5793054D28278A5DE6d4653EC79e90FE"),
            hex!("3B8E75804F71e121008991E3177fc942b6c28F50"),
            hex!("C6Eb5886eB43dD473f5BB4e21e56E08dA464D9B4"),
            hex!("fdf1277b71A73c813cD0e1a94B800f4B1Db66DBE"),
            hex!("c2ff2cCc98971556670e287Ff0CC39DA795231ad"),
            hex!("76b7E1473f0D0A87E9B4a14E2B179266802740f5"),
            hex!("A7Bc965660a6EF4687CCa4F69A97563163A3C2Ef"),
            hex!("B9C2b47888B9F8f7D03dC1de83F3F55E738CebD3"),
            hex!("Ed400162E6Dd6bD2271728FFb04176bF770De94a"),
            hex!("E3E8331156700339142189B6E555DCb2c0962750"),
            hex!("bf62e342Bc7706a448EdD52AE871d9C4497A53b1"),
            hex!("b9d7A1A111eed75714a0AcD2dd467E872eE6B03D"),
            hex!("03942919DFD0383b8c574AB8A701d89fd4bfA69D"),
            hex!("0Ef4C92355D3c8c7050DFeb319790EFCcBE6fe9e"),
            hex!("A6895a3cf0C60212a73B3891948ACEcF1753f25E"),
            hex!("0Ed509239DB59ef3503ded3d31013C983d52803A"),
            hex!("c4CE8abD123BfAFc4deFf37c7D11DeCd5c350EE4"),
            hex!("4A4Bf59f7038eDcd8597004f35d7Ee24a7Bdd2d3"),
            hex!("5769E8e8A2656b5ed6b6e6fa2a2bFAeaf970BB87"),
            hex!("f9E15cCE181332F4F57386687c1776b66C377060"),
            hex!("c98f8d4843D56a46C21171900d3eE538Cc74dbb5"),
            hex!("3605965B47544Ce4302b988788B8195601AE4dEd"),
            hex!("e993BDfdcAac2e65018efeE0F69A12678031c71d"),
            hex!("274fDf8801385D3FAc954BCc1446Af45f5a8304c"),
            hex!("BFb3f476fcD6429F4a475bA23cEFdDdd85c6b964"),
            hex!("806cD16588Fe812ae740e931f95A289aFb4a4B50"),
            hex!("a89488CE3bD9C25C3aF797D1bbE6CA689De79d81"),
            hex!("d412f1AfAcf0Ebf3Cd324593A231Fc74CC488B12"),
            hex!("d1f715b2D7951d54bc31210BbD41852D9BF98Ed1"),
            hex!("f65aD707c344171F467b2ADba3d14f312219cE23"),
            hex!("2971a4b242e9566dEF7bcdB7347f5E484E11919B"),
            hex!("12b113D6827E07E7D426649fBd605f427da52314"),
            hex!("1c6CA45171CDb9856A6C9Dba9c5F1216913C1e97"),
            hex!("11cC6ee1d74963Db23294FCE1E3e0A0555779CeA"),
            hex!("8Aa1C721255CDC8F895E4E4c782D86726b068667"),
            hex!("A2cDC1f37510814485129aC6310b22dF04e9Bbf0"),
            hex!("Cf531b71d388EB3f5889F1f78E0d77f6fb109767"),
            hex!("Be703e3545B2510979A0cb0C440C0Fba55c6dCB5"),
            hex!("30a35886F989db39c797D8C93880180Fdd71b0c8"),
            hex!("1071370D981F60c47A9Cd27ac0A61873a372cBB2"),
            hex!("3515d74A11e0Cb65F0F46cB70ecf91dD1712daaa"),
            hex!("50500a3c2b7b1229c6884505D00ac6Be29Aecd0C"),
            hex!("9A223c2a11D4FD3585103B21B161a2B771aDA3d1"),
            hex!("d7218df03AD0907e6c08E707B15d9BD14285e657"),
            hex!("76CfD72eF5f93D1a44aD1F80856797fBE060c70a"),
            hex!("44d093cB745944991EFF5cBa151AA6602d6f5420"),
            hex!("626516DfF43bf09A71eb6fd1510E124F96ED0Cde"),
            hex!("6530824632dfe099304E2DC5701cA99E6d031E08"),
            hex!("57e6c423d6a7607160d6379A0c335025A14DaFC0"),
            hex!("3966D4AD461Ef150E0B10163C81E79b9029E69c3"),
            hex!("F608aCfd0C286E23721a3c347b2b65039f6690F1"),
            hex!("bfB8FAac31A25646681936977837f7740fCd0072"),
            hex!("d80aa634a623a7ED1F069a1a3A28a173061705c7"),
            hex!("9122a77B36363e24e12E1E2D73F87b32926D3dF5"),
            hex!("62562f0d1cD31315bCCf176049B6279B2bfc39C2"),
            hex!("48aBF7A2a7119e5675059E27a7082ba7F38498b2"),
            hex!("b4596983AB9A9166b29517acD634415807569e5F"),
            hex!("52519D16E20BC8f5E96Da6d736963e85b2adA118"),
            hex!("7663893C3dC0850EfC5391f5E5887eD723e51B83"),
            hex!("5FF323a29bCC3B5b4B107e177EccEF4272959e61"),
            hex!("ee6e499AdDf4364D75c05D50d9344e9daA5A9AdF"),
            hex!("1631b0BD31fF904aD67dD58994C6C2051CDe4E75"),
            hex!("bc208e9723D44B9811C428f6A55722a26204eEF2"),
            hex!("e76103a222Ee2C7Cf05B580858CEe625C4dc00E1"),
            hex!("C71Bb2DBC51760f4fc2D46D84464410760971B8a"),
            hex!("B4C18811e6BFe564D69E12c224FFc57351f7a7ff"),
            hex!("D11DB0F5b41061A887cB7eE9c8711438844C298A"),
            hex!("B931269934A3D4432c084bAAc3d0de8143199F4f"),
            hex!("070037cc85C761946ec43ea2b8A2d5729908A2a1"),
            hex!("2E34aa8C95Ffdbb37f14dCfBcA69291c55Ba48DE"),
            hex!("052D93e8d9220787c31d6D83f87eC7dB088E998f"),
            hex!("498dAC6C69b8b9ad645217050054840f1D91D029"),
            hex!("E4F7D60f9d84301e1fFFd01385a585F3A11F8E89"),
            hex!("Ea637992f30eA06460732EDCBaCDa89355c2a107"),
            hex!("4960d8Da07c27CB6Be48a79B96dD70657c57a6bF"),
            hex!("7e471A003C8C9fdc8789Ded9C3dbe371d8aa0329"),
            hex!("d24265Cc10eecb9e8d355CCc0dE4b11C556E74D7"),
            hex!("DE59C8f7557Af779674f41CA2cA855d571018690"),
            hex!("2fA8A6b3b6226d8efC9d8f6EBDc73Ca33DDcA4d8"),
            hex!("e44102664c6c2024673Ff07DFe66E187Db77c65f"),
            hex!("94E3f4f90a5f7CBF2cc2623e66B8583248F01022"),
            hex!("0383EdBbc21D73DEd039E9C1Ff6bf56017b4CC40"),
            hex!("64C3E49898B88d1E0f0d02DA23E0c00A2Cd0cA99"),
            hex!("F4ccfB67b938d82B70bAb20975acFAe402E812E1"),
            hex!("4f9ee5829e9852E32E7BC154D02c91D8E203e074"),
            hex!("b006312eF9713463bB33D22De60444Ba95609f6B"),
            hex!("7Cbe76ef69B52110DDb2e3b441C04dDb11D63248"),
            hex!("70ADEEa65488F439392B869b1Df7241EF317e221"),
            hex!("64C0bf8AA36Ba590477585Bc0D2BDa7970769463"),
            hex!("A4cDc98593CE52d01Fe5Ca47CB3dA5320e0D7592"),
            hex!("c26B34D375533fFc4c5276282Fa5D660F3d8cbcB"),
        ]
        .iter()
        .map(|h| keccak256(&h))
        .collect::<Vec<[u8; 32]>>();

        let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);

        let leaves = vec![0, 2, 5, 9, 20, 25, 31];
        let leaves_with_indices = leaves
            .iter()
            .map(|i| {
                Token::Tuple(vec![
                    Token::Uint(U256::from(*i)),
                    Token::FixedBytes(leaf_hashes[*i].to_vec()),
                ])
            })
            .collect::<Vec<_>>();

        let proof = tree.proof_2d(&leaves);

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

        let calculated = execute::<_, [u8; 32]>(
            &mut runner,
            "MerkleTests",
            "CalculateRoot",
            (args, leaves_with_indices),
        )
        .unwrap();

        assert_eq!(tree.root().unwrap(), calculated)
    }

    #[test]
    fn test_mmr_utils() {
        let mut runner = runner();

        let leading_zeros = execute::<_, U256>(
            &mut runner,
            "MerkleTests",
            "countLeadingZeros",
            (Token::Uint(U256::from(17))),
        )
        .unwrap();

        assert_eq!(leading_zeros.as_u32(), 17u64.leading_zeros());

        let count_zeros = execute::<_, U256>(
            &mut runner,
            "MerkleTests",
            "countZeroes",
            (Token::Uint(U256::from(17))),
        )
        .unwrap();

        assert_eq!(count_zeros.as_u32(), 17u64.count_zeros());

        let count_ones = execute::<_, U256>(
            &mut runner,
            "MerkleTests",
            "countOnes",
            (Token::Uint(U256::from(17))),
        )
        .unwrap();

        assert_eq!(count_ones.as_u32(), 17u64.count_ones());

        {
            for pos in [45, 98, 200, 412] {
                let height = execute::<_, U256>(
                    &mut runner,
                    "MerkleTests",
                    "posToHeight",
                    (Token::Uint(U256::from(pos))),
                )
                .unwrap();

                assert_eq!(height.as_u32(), pos_height_in_tree(pos));
            }
        }

        {
            let left = vec![3, 4].into_iter().map(|n| Token::Uint(U256::from(n))).collect();
            let right = vec![2, 5].into_iter().map(|n| Token::Uint(U256::from(n))).collect();

            let height = execute::<_, Vec<u64>>(
                &mut runner,
                "MerkleTests",
                "difference",
                (Token::Array(left), Token::Array(right)),
            )
            .unwrap();

            assert_eq!(height, vec![3, 4]);
        }

        {
            let indices =
                vec![2, 5].into_iter().map(|i| Token::Uint(U256::from(i))).collect::<Vec<_>>();
            let siblings =
                execute::<_, Vec<u64>>(&mut runner, "MerkleTests", "siblingIndices", (indices))
                    .unwrap();

            assert_eq!(siblings, vec![3, 4]);
        }

        {
            let leaves = vec![
                (3, 2, hex!("2b97a4b75a93aa1ac8581fac0f7d4ab42406569409a737bdf9de584903b372c5")),
                (8, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
                (14, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
                (22, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
                (25, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
                (30, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
            ]
            .into_iter()
            .map(|(pos, index, hash)| {
                Token::Tuple(vec![
                    Token::Uint(U256::from(index)),
                    Token::Uint(U256::from(pos)),
                    Token::FixedBytes(hash.to_vec()),
                ])
            })
            .collect::<Vec<_>>();

            let result = execute::<_, (Vec<(u64, [u8; 32])>, Vec<u64>)>(
                &mut runner,
                "MerkleTests",
                "mmrLeafToNode",
                (leaves.clone()),
            )
            .unwrap();

            assert_eq!(result.0.len(), 6);
            assert_eq!(result.1.len(), 6);

            let result = execute::<_, (Vec<MmrLeaf>, Vec<MmrLeaf>)>(
                &mut runner,
                "MerkleTests",
                "leavesForPeak",
                (leaves, Token::Uint(U256::from(15))),
            )
            .unwrap();

            assert_eq!(result.0.len(), 3);
            assert_eq!(result.1.len(), 3);
        }

        {
            for pos in [45, 98, 200, 412] {
                let peaks = execute::<_, Vec<u64>>(
                    &mut runner,
                    "MerkleTests",
                    "getPeaks",
                    (Token::Uint(U256::from(pos))),
                )
                .unwrap();

                assert_eq!(peaks, get_peaks(pos));
            }
        }
    }

    #[test]
    fn test_merkle_mountain_range() {
        let mut runner = runner();

        let store = MemStore::default();
        let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
        let positions: Vec<u64> =
            (0u32..=13).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
        let proof = mmr
            .gen_proof(vec![positions[2], positions[5], positions[8], positions[10], positions[12]])
            .unwrap();

        let leaves = vec![
            (NumberHash::from(2), positions[2]),
            (NumberHash::from(5), positions[5]),
            (NumberHash::from(8), positions[8]),
            (NumberHash::from(10), positions[10]),
            (NumberHash::from(12), positions[12]),
        ]
        .into_iter()
        .map(|(a, b)| (b, a))
        .collect::<Vec<_>>();

        let positions = leaves.iter().map(|(pos, _)| *pos).collect();
        let pos_with_index = mmr_position_to_k_index(positions, proof.mmr_size());

        let mut custom_leaves = pos_with_index
            .into_iter()
            .zip(leaves.clone())
            .map(|((pos, index), (_, leaf))| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&leaf.0);
                (pos, index, hash)
            })
            .collect::<Vec<_>>();

        custom_leaves.sort_by(|(a_pos, _, _), (b_pos, _, _)| a_pos.cmp(b_pos));

        let token_leaves = custom_leaves
            .into_iter()
            .map(|(pos, index, hash)| {
                Token::Tuple(vec![
                    Token::Uint(U256::from(index)),
                    Token::Uint(U256::from(pos)),
                    Token::FixedBytes(hash.to_vec()),
                ])
            })
            .collect::<Vec<_>>();

        let nodes = proof
            .proof_items()
            .iter()
            .map(|n| Token::FixedBytes(n.0.clone()))
            .collect::<Vec<_>>();

        let root = execute::<_, [u8; 32]>(
            &mut runner,
            "MerkleTests",
            "calculateRoot",
            (nodes, token_leaves, Token::Uint(mmr.mmr_size().into())),
        )
        .unwrap();

        assert_eq!(root.to_vec(), mmr.get_root().unwrap().0);
    }
}
