// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import "solmate/tokens/ERC721.sol";
import "solmate/utils/ReentrancyGuard.sol";
import "./ISneakyAuctionErrors.sol";
import "./LibBalanceProof.sol";
import "./SneakyMultiAuctionLib.sol";
import "./SneakyMultiVault.sol";
import "morpho-data-structures/DoubleLinkedList.sol";
import "solmate/utils/SafeTransferLib.sol";

/// @title An on-chain, exact-collateralization, sealed-bid, second-price auction
contract SneakyMultiAuction is
    ISneakyAuctionErrors,
    ISneakyMultiAuction,
    ReentrancyGuard
{
    using SafeTransferLib for address payable;
    using SneakyMultiAuctionLib for SneakyMultiAuctionLib.Auction;
    using DoubleLinkedList for DoubleLinkedList.List;

    DoubleLinkedList.List public winners;
    mapping(address => SneakyMultiAuctionLib.RevealedVault)
        public revealedVaults;

    function processVault(IAuctionCallback callback) external payable {
        address bidder = revealedVaults[msg.sender].bidder;
        if (bidder == address(0)) {
            revert CallerNotAVault();
        }
        if (!winners.contains(msg.sender)) {
            payable(msg.sender).safeTransferETH(msg.value);
            return;
        }

        uint256 clearingPrice = winners.getValueOf(winners.getSmallest());
        assert(msg.value >= clearingPrice);

        // Griefing protection is implemented in the caller, SneakyMultiVault.
        callback.processWinningBid{value: clearingPrice}(bidder);

        payable(msg.sender).safeTransferETH(msg.value - clearingPrice);
    }
}
