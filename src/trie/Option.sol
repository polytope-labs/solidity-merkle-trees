pragma solidity ^0.8.17;

import "./Node.sol";

// SPDX-License-Identifier: Apache2

library Option {
    function isSome(ValueOption memory val) internal pure returns (bool) {
        return val.isSome == true;
    }

    function isSome(NodeHandleOption memory val) internal pure returns (bool) {
        return val.isSome == true;
    }
}
