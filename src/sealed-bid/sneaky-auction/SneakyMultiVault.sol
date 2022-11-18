// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import {ISneakyMultiAuction, IAuctionCallback} from "./SneakyMultiAuctionLib.sol";

/// @title A contract deployed via `CREATE2` by the `SneakyMultiAuction` contract. Bidders
///        send their collateral to the address of the SneakyVault before it is deployed.
contract SneakyMultiVault {
    /// @dev Both the IAuctionCallback and the bidValue are unused by the
    /// constructor but exist to commit to the specific auction and bid amount
    /// because `CREATE2` includes constructor args in determining the address.
    constructor(
        IAuctionCallback callback,
        address bidder,
        uint48 /* bidValue in SneakyMultiAuctionLib.BID_BASE_UNITs */
    ) {
        // The `SneakyMultiAuction` has a record of vaults that it has deployed,
        // acting as protection against malicious calling of processVault(). It
        // returns any unused balance (all if this vault loses the auction, or
        // balance - clearingPrice) if it wins.
        /// TODO: PROTECT against griefing
        ISneakyMultiAuction(msg.sender).processVault{
            value: address(this).balance
        }(callback);

        selfdestruct(payable(bidder));
    }
}
