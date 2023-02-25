pragma solidity ^0.8.17;

import "./Node.sol";

// SPDX-License-Identifier: Apache2

library Option {
    function isSome(ValueOption memory val) public pure returns (bool)  {
        return val.isSome == true;
    }

    function isSome(NodeHandleOption memory val) public pure returns (bool)  {
        return val.isSome == true;
    }
}