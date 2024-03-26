// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "forge-std/Test.sol";

import "../src/MerklePatricia.sol";
import "../src/trie/substrate/SubstrateTrieDB.sol";
import "../src/trie/substrate/ScaleCodec.sol";
import "../src/trie/NibbleSlice.sol";
import "../src/trie/Bytes.sol";

contract MerklePatriciaTest is Test {
    function testSubstrateMerklePatricia() public pure {
        bytes[] memory keys = new bytes[](1);
        // trie key for pallet_timestamp::Now
        keys[0] = hex"f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb";

        bytes[] memory proof = new bytes[](2);
        proof[0] =
            hex"802e98809b03c6ae83e3b70aa89acfe0947b3a18b5d35569662335df7127ab8fcb88c88780e5d1b21c5ecc2891e3467f6273f27ce2e73a292d6b8306197edfa97b3d965bd080c51e5f53a03d92ea8b2792218f152da738b9340c6eeb08581145825348bbdba480ad103a9320581c7747895a01d79d2fa5f103c4b83c5af10b0a13bc1749749523806eea23c0854ced8445a3338833e2401753fdcfadb3b56277f8f1af4004f73719806d990657a5b5c3c97b8a917d9f153cafc463acd90592f881bc071d6ba64e90b380346031472f91f7c44631224cb5e61fb29d530a9fafd5253551cbf43b7e97e79a";
        proof[1] =
            hex"9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2035e90c7f86010000";

        bytes32 root = hex"6b5710000eccbd59b6351fc2eb53ff2c1df8e0f816f7186ddd309ca85e8798dd";
        bytes memory value = MerklePatricia.VerifySubstrateProof(root, proof, keys)[0].value;
        uint256 timestamp = ScaleCodec.decodeUint256(value);
        assert(timestamp == 1677168798005);
    }

    function testSubstrateMerklePatriciaSingleNode() public {
        bytes[] memory keys = new bytes[](1);
        // trie key for pallet_timestamp::Now
        keys[0] = hex"00";

        bytes[] memory proof = new bytes[](1);
        proof[0] =
            hex"8100110034402c280401000b5db899138701804f1dc18c0729c67df638dcb17ff86372be663d0d85339a845510498c6c42fc3b";

        bytes32 root = hex"9ec7b55dd538898d95dec220abf8f60e8c626bdb4a348d117d1ecaa564cb565c";
        bytes memory value = MerklePatricia.VerifySubstrateProof(root, proof, keys)[0].value;
        assertEq(ScaleCodec.decodeUintCompact(ByteSlice(value, 4)), 1679661054045);
    }

    function testEthereumMerklePatricia() public {
        bytes[] memory keys = new bytes[](1);
        // slot at 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc        
        keys[0] = hex"75b20eef8615de99c108b05f0dbda081c91897128caa336d75dffb97c4132b4d";

        // proof from account 0xbEb5Fc579115071764c7423A4f12eDde41f106Ed on Ethreum mainnet at block 19458609
        bytes[] memory proof = new bytes[](7);
        proof[0] =
            hex"f90211a0e36cd4c05239f5c535a7840f9f14b74bf287328e3fb87d09f02355e644f4378fa0fa16c734775c7d81b5d459addf9cf6ef8c8e20b71a4df4754c6be3895cf20977a0ec900883398b84efcb12fee51e991e878fac4ce09c6cc07c8d0c0941398a3664a01de14c6cc89ac9ba2e5294a300c5497bb6817f7481e68febf3975a8b017e5c15a010765286a0f030df2b4e13c82eb2c95fb2f865e1e5ae67fb19fbadc4c554771da0f5cac85a41291eb814b14706fa3d27c6f8890ce2fed6f92ef03b6e8d22e093f8a0ff187925da588f90250b7680887c3d8d155b51f58112a0cfdc6356884c60d4eaa06b82977e5bb3457a89b79f252f3f448817761c03e14fdd99988d0d71a914fb96a0d0ed46c3bf3a217660177d3c0f3744aa40d3a67ed4dabe5371dcd101ebcb71d7a02d642b6a1035a17fca9ea16138d6ede364da0af4b2c5c362360e3b3669e96a7da0768a6012c6be41406374fa24604b803906c2dc3421d6aa9752fddcd7042ddb94a09c139cf4bbd79b32c255928ff267ee22948d06976efbc0ac869cb5a674857917a06e617a3e1bc92d939a0b6feff4c8d688f74315af5cecfb9a2869267b326a8ba6a078368124e1131b2743d0fbdda3b1b0c0a8adedb1b8839bb99fd31e34d50d1922a0dccc4ddd77c9580f1443dfd64c2d6a22014ba2dccd81281e6663f488c3447e21a0dfaeb0b02df962296d9e0645c2ae2961e15d0d1d92392164624a502cad96fd9480";
        proof[1] =
            hex"f90211a0486fcee760e354cec03ba3a431a9f035417f63c957ea05b33cf49e3afaef8741a08ef7adc166a1423cb4f035d5a83583726cd5803405a4b8684ad0c023203ce6a7a098d08b44d840f34fa68397f2a5453c4eb89e86195f96ccadfe14de7925664561a0817d070ecb8e3451a505c6f9d008db91763c68f186346dd4555962bbba4abe03a0115d9190622849e9205a96f863707032e29621447c34506145efc434dac91321a0298e4f7519bea373ceb5f94cb34d78383c4664e2f5beac262b01b428c3b2a280a0c0ff7e3638c51912db91d92a6d637a2c8bbcae73fe33bf3738db40369763e5aba0fde04f5dc892f5156e5b1fd7985e90d9c64330d439645b80311561a370338ef9a09bd1e2ef9548cacf1ce0057f13c93344300849fbca2638f3055bdf638d59948ea078a2c1a862906b603291741138bee56444fd3f34e6a4f3ca1f0e318429a94862a08ecc44cc4a06c9a7ac2e21860942750ada47e14e2f2efd561d03104525ba27aaa08d407dec2d5527e80d6d73e8ee8c1ef8cd8819bd82628faf93abe454f48b8a7ca0bf759b30dbbf0e5e6a3c5bc258a91b7c6778e6f0b474e7fdb4117c1659ea5774a06b30bcd113d0d3ea46f1134654f7172ccf7253d17397ed0e57847cb14f1a4a64a0c2b47985c05a2eb85463fc687d7e09bb8aafddf1c57a323652b04a9b791d76c9a0d65a53fe9963a9086bc3c7796aa30286f029b01814f561ff98f1f4b898ad264380";
        proof[2] =
            hex"f90211a0496f94fb20f86b96949c1e8ff21646543893848e9ba0fc88c29989993d6f4733a0346f2b92631b4ccec787638be96dce0f9082650f6839f951b4003282f0ea2934a0ddd5e6839f84a978019b8e076dc6057c579e3951ef766dcfb3342b251c424ee4a04feb7109266fd467e79012fada3159bad47d478612b15c812d853b5bbfb038cea083181482a9c3349b408b2cb957b78dd71aa9faf842d727e889afbf8d2e8f5fe2a0d417081e6c2f8b46bfa50ada78eb44bd87d620e834d5107055567f383ef04427a001d74013d6ab118109e0b4f6d3be65dbf5d16857cdd7e7f2698ef28a06177b9aa075bb8b6d0cffe800afd4dc0df14cffe73140cce5c716e75fb56bb65db4b403f4a055db1b1c8e3760650d578218fb0787d80b56295ce5e302515d5c300217f5179ba0c338b90051d671575d53c2cee1bd88fc422e7b84d7fa7fb8e0ae9c414382b1e0a03c2f2bb41a5f16e318785c263dc7811b17f4efaee0c6ca2645364259cbcb8487a0bdb8ff1b3ab9c0ef2cb6d22eb12cb0883a040b5a331cb3e178310bf052753552a00d8dcb4eab5db9a22b7a31d5cdf9a67c02b959f4f4ae49d325a6597622586859a0db07ac1cc177e0b96f40fda37b035e3954f0890942d6286fb18b6a9ca9e0a7dda033db3178750e7f06f808461292ddf275697492a5df3a13f25e7e6afb6d31ca70a0a81061197b9e888f84b6e647eebddee898f41c7056e8f878e9a4cd1c27c65e5980";
        proof[3] =
            hex"f8f1a0b9bbfd6ce22f4ae072ef3d74361ee4264c93d20f2db91820d80e7241a2fad769a021681b13bd0228de9fc4094fe565dfe7edd4904bac9aad26ed2a7f2bf8acea0fa00944ff72f3186a894ecbd5e4990ae7cf28d3014cfa2dfebb42a703218c5b5e808080808080a05500178fdbdbd39144f93e0bb3c5b1304337ed6b72a0898e4e951c4f2565637d808080a0e7b6274092da49eb53015db452d82ba172bd098ef90653d812dbcc32df8afb72a08a93d8b68d7ec95d2fe990bb6503309cc116a435f05ee710a24fc82f68c2c00f80a076be6f941a705872dfb43bca24baaa291663ad1332f60b9f28a7c111c941592c80";
        proof[4] =
            hex"e210a0b798089c35eabfa9992866d0ff2d19040e85326547b79dad85be810b5482bfb2";
        proof[5] =
            hex"f851808080808080808080a03b00a9adfccdbcb4252a987ba894a37829d4d2d5bf4f30740ac23f93a22510ab80808080a07904f9b847c710858697e144376dab844c380807ecf4b6b7364c57fc22a86ed18080";
        proof[6] =
            hex"f59e20ef8615de99c108b05f0dbda081c91897128caa336d75dffb97c4132b4d9594ababe63514ddd6277356f8cc3d6518aa8bdeb4de";

        bytes32 root = hex"c162613853b0d814a7aaaf9869f44cad1aab4cb151321da5c60ff3a2ddc14daf";
        bytes memory value = VerifyEthereum(root, proof, keys)[0].value;
        bytes memory expectedOutput = hex"94ababe63514ddd6277356f8cc3d6518aa8bdeb4de";
        assertEq(value, expectedOutput);
    }

    function VerifyKeys(bytes32 root, bytes[] memory proof, bytes[] memory keys)
        public
        pure
        returns (StorageValue[] memory)
    {
        return MerklePatricia.VerifySubstrateProof(root, proof, keys);
    }

    function VerifyEthereum(bytes32 root, bytes[] memory proof, bytes[] memory keys)
        public
        pure
        returns (StorageValue[] memory)
    {
        return MerklePatricia.VerifyEthereumProof(root, proof, keys);
    }

    function decodeNodeKind(bytes memory node) public pure returns (NodeKind memory) {
        return SubstrateTrieDB.decodeNodeKind(node);
    }

    function decodeNibbledBranch(bytes memory node) external pure returns (NibbledBranch memory) {
        return SubstrateTrieDB.decodeNibbledBranch(SubstrateTrieDB.decodeNodeKind(node));
    }

    function decodeLeaf(bytes memory node) external pure returns (Leaf memory) {
        return SubstrateTrieDB.decodeLeaf(SubstrateTrieDB.decodeNodeKind(node));
    }

    function nibbleLen(NibbleSlice memory nibble) public pure returns (uint256) {
        return NibbleSliceOps.len(nibble);
    }

    function mid(NibbleSlice memory self, uint256 i) public pure returns (NibbleSlice memory) {
        return NibbleSliceOps.mid(self, i);
    }

    function isNibbleEmpty(NibbleSlice memory self) public pure returns (bool) {
        return NibbleSliceOps.isEmpty(self);
    }

    function eq(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return NibbleSliceOps.eq(self, other);
    }

    function nibbleAt(NibbleSlice memory self, uint256 i) public pure returns (uint256) {
        return NibbleSliceOps.at(self, i);
    }

    function startsWith(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return NibbleSliceOps.startsWith(self, other);
    }

    function commonPrefix(NibbleSlice memory self, NibbleSlice memory other) public pure returns (uint256) {
        return NibbleSliceOps.commonPrefix(self, other);
    }
}
