// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.13;

import "solmate/tokens/ERC721.sol";
import "solmate/utils/ReentrancyGuard.sol";
import "./ISneakyAuctionErrors.sol";
import "./LibBalanceProof.sol";
import {SneakyMultiVault} from "./SneakyMultiVault.sol";
import {DoubleLinkedList} from "morpho-data-structures/DoubleLinkedList.sol";
import {ISneakyAuctionErrors} from "./ISneakyAuctionErrors.sol";

interface IAuctionCallback {
    /**
     * @dev Must check that it is only called by an authorised auction contract.
     */
    function processWinningBid(address bidder) external payable;
}

interface ISneakyMultiAuction {
    function processVault(IAuctionCallback callback) external payable;
}

/// @title An on-chain, exact-collateralization, sealed-bid, k-Vickrey auction.
library SneakyMultiAuctionLib {
    using SneakyMultiAuctionLib for SneakyMultiAuctionLib.Auction;
    using DoubleLinkedList for DoubleLinkedList.List;

    /// @notice The base unit for bids. The reserve price and bid value parameters
    ///         for this contract's functions are denominated in this base unit,
    ///         _not_ wei. 1000 gwei = 1e12 wei.
    uint256 public constant BID_BASE_UNIT = 1000 gwei;

    uint256 public constant MAX_ITERATIONS_DLL_INSERTION = 100;

    /// @dev Representation of an auction in storage. Occupies three slots.
    /// @param callback The address called to process winning bids.
    /// @param endOfBiddingPeriod The unix timestamp after which bids can no
    ///        longer be placed.
    /// @param endOfRevealPeriod The unix timestamp after which commitments can
    ///        no longer be opened.
    /// @param index Auctions selling the same asset (i.e. tokenContract-tokenId
    ///        pair) share the same storage. This value is incremented for
    ///        each new auction of a particular asset.
    /// @param highestBid The value of the highest bid revealed so far, or
    ///        the reserve price if no bids have exceeded it. In bid base units
    ///        (1000 gwei).
    /// @param secondHighestBid The value of the second-highest bid revealed
    ///        so far, or the reserve price if no two bids have exceeded it.
    ///        In bid base units (1000 gwei).
    /// @param highestBidVault The address of the `SneakyMultiVault` containing
    ///        the collateral for the highest bid.
    /// @param collateralizationDeadlineBlockHash The hash of the block considered
    ///        to be the deadline for collateralization. This is set when the first
    ///        bid is revealed, and all other bids must have been collateralized
    ///        before the deadline block.
    struct Auction {
        IAuctionCallback callback;
        uint32 endOfBiddingPeriod;
        uint32 endOfRevealPeriod;
        // =====================
        uint32 lotSize;
        uint32 numWinningBids;
        uint48 reservePrice;
        // =====================
        bytes32 collateralizationDeadlineBlockHash;
    }

    struct RevealedVault {
        address bidder;
        // 96 bits of security is sufficient for the duration of an auction.
        uint96 salt;
    }

    /// @dev A Merkle proof and block header, in conjunction with the
    ///      stored `collateralizationDeadlineBlockHash` for an auction,
    ///      is used to prove that a bidder's `SneakyMultiVault` was sufficiently
    ///      collateralized by the time the first bid was revealed.
    /// @param accountMerkleProof The Merkle proof of a particular account's
    ///        state, as returned by the `eth_getProof` RPC method.
    /// @param blockHeaderRLP The RLP-encoded header of the block
    ///        for which the account balance is being proven.
    struct CollateralizationProof {
        bytes[] accountMerkleProof;
        bytes blockHeaderRLP;
    }

    /// @notice Emitted when an auction is created.
    /// @param callback The address called to process winning bids.
    /// @param bidPeriod The duration of the bidding period, in seconds.
    /// @param revealPeriod The duration of the commitment reveal period,
    ///        in seconds.
    /// @param reservePrice The minimum price (in wei) that the asset will be sold
    ///        for. If not bids exceed this price, the asset is returned to `seller`.
    event AuctionCreated(
        IAuctionCallback callback,
        uint32 bidPeriod,
        uint32 revealPeriod,
        uint256 reservePrice
    );

    /// @notice Emitted when a bid is revealed.
    /// @param callback The address called to process winning bids.
    /// @param bidVault The vault holding the bid collateral.
    /// @param bidder The bidder whose bid was revealed.
    /// @param salt The random input used to obfuscate the commitment.
    /// @param bidValue The value of the bid in wei.
    event BidRevealed(
        IAuctionCallback callback,
        address bidVault,
        address bidder,
        uint96 salt,
        uint256 bidValue
    );

    /// @notice Emitted when the first bid is revealed for an auction. All
    ///         subsequent bid openings must submit a Merkle proof that their
    ///         vault was sufficiently collateralized by the deadline block.
    /// @param callback The address called to process winning bids.
    /// @param deadlineBlockNumber The block number by which bidders' vaults
    ///        must have been collateralized.
    event CollateralizationDeadlineSet(
        IAuctionCallback callback,
        uint256 deadlineBlockNumber
    );

    /// @notice Creates an auction for the given ERC721 asset with the given
    ///         auction parameters.
    /// @param callback The address called to process winning bids.
    /// @param bidPeriod The duration of the bidding period, in seconds.
    /// @param revealPeriod The duration of the commitment reveal period,
    ///        in seconds.
    /// @param reservePrice The minimum price that the asset will be sold for.
    ///        If not bids exceed this price, the asset is returned to `seller`.
    ///        In bid base units (1000 gwei).
    function createAuction(
        IAuctionCallback callback,
        uint32 bidPeriod,
        uint32 revealPeriod,
        uint48 reservePrice
    ) internal returns (Auction memory) {
        Auction memory auction;
        auction.callback = callback;

        if (bidPeriod < 1 hours) {
            revert ISneakyAuctionErrors.BidPeriodTooShortError(bidPeriod);
        }
        if (revealPeriod < 1 hours) {
            revert ISneakyAuctionErrors.RevealPeriodTooShortError(revealPeriod);
        }

        auction.endOfBiddingPeriod = uint32(block.timestamp) + bidPeriod;
        auction.endOfRevealPeriod =
            uint32(block.timestamp) +
            bidPeriod +
            revealPeriod;

        auction.reservePrice = reservePrice;
        auction.collateralizationDeadlineBlockHash = bytes32(0);

        emit AuctionCreated(
            auction.callback,
            bidPeriod,
            revealPeriod,
            reservePrice * BID_BASE_UNIT
        );

        return auction;
    }

    /// @notice Reveals the value of a bid that was previously committed to.
    /// @param bidValue The value of the bid. In bid base units (1000 gwei).
    /// @param salt The random input used to obfuscate the commitment.
    /// @param proof The proof that the vault corresponding to this bid was
    ///        sufficiently collateralized before any bids were revealed. This
    ///        may be null if this is the first bid revealed for the auction.
    /// @param hintGT The currently next highest bid (or 0 if none revealed) to
    ///        minimise the searching needed to insert this bid. See equivalent
    ///        DoubleLinkedList.List.insertSorted param.
    function revealBid(
        Auction memory auction,
        DoubleLinkedList.List storage winners,
        mapping(address => RevealedVault) storage revealedVaults,
        uint48 bidValue,
        uint96 salt,
        CollateralizationProof calldata proof,
        address hintGT
    ) external {
        if (
            block.timestamp <= auction.endOfBiddingPeriod ||
            block.timestamp > auction.endOfRevealPeriod
        ) {
            revert ISneakyAuctionErrors.NotInRevealPeriodError();
        }

        address vault = getVaultAddress(
            auction.callback,
            msg.sender,
            bidValue,
            salt
        );

        if (revealedVaults[vault].bidder != address(0)) {
            revert ISneakyAuctionErrors.BidAlreadyRevealedError(vault);
        }
        revealedVaults[vault] = RevealedVault({bidder: msg.sender, salt: salt});

        uint256 bidValueWei = bidValue * BID_BASE_UNIT;
        // If this is the first bid revealed, record the block hash of the
        // previous block. All other bids must have been collateralized by
        // that block.
        if (auction.collateralizationDeadlineBlockHash == bytes32(0)) {
            // As the first bid revealed, we don't care when the vault was
            // collateralized (e.g. this block). With the exception of racing
            // `revealBid` transactions in the public mempool, the bidder
            // shouldn't be able to gain additional info about other bids
            // by waiting until this block to collateralize.
            if (vault.balance < bidValueWei) {
                // Deploy vault to return ETH to bidder
                auction.clearBid(salt, msg.sender, bidValue);
                return;
            } else {
                auction.collateralizationDeadlineBlockHash = blockhash(
                    block.number - 1
                );
                emit CollateralizationDeadlineSet(
                    auction.callback,
                    block.number - 1
                );
            }
        } else {
            // All other bidders must prove that their balance was
            // sufficiently collateralized by the deadline block.
            uint256 vaultBalance = LibBalanceProof.getProvenAccountBalance(
                proof.accountMerkleProof,
                proof.blockHeaderRLP,
                auction.collateralizationDeadlineBlockHash,
                vault
            );

            if (vaultBalance < bidValueWei) {
                // Deploy vault to return ETH to bidder
                auction.clearBid(salt, msg.sender, bidValue);
                return;
            }
        }

        if (bidValue < auction.reservePrice) {
            auction.clearBid(salt, msg.sender, bidValue);
            return;
        }

        // A tie-break mechanism based on randomness. Left-shift all bids and
        // add some entropy in the least-significant portion; this maintains
        // ordering of otherwise unequal bid values, while ensuring that
        // previously equal bids are no longer so.
        //
        // TODO: assess the security of this entropy source. The only
        // participant who can exert any control over this is the first revealer
        // but they're at the mercy of the previous blocks and also in a race
        // with others. All said, the benefit of gaming this is, at best, to
        // increase an effective bid by BID_BASE_UNIT (1000 gwei) so it's easier
        // to simply bid more to begin with!
        uint256 bidValueShifted = ((uint256(bidValue) << 160) +
            (uint256(auction.collateralizationDeadlineBlockHash) >> 96)) ^
            uint256(uint160(vault));

        if (auction.numWinningBids < auction.lotSize) {
            winners.insertSorted(
                vault,
                bidValueShifted,
                MAX_ITERATIONS_DLL_INSERTION,
                hintGT
            );
            auction.numWinningBids++;
        } else {
            address smallestVault = winners.getSmallest();
            uint256 smallestBidValueShifted = winners.getValueOf(smallestVault);

            // Bid value is smaller than the smallest winning bid. Refund.
            if (bidValueShifted < smallestBidValueShifted) {
                auction.clearBid(salt, msg.sender, bidValue);
            } else {
                winners.insertSorted(
                    vault,
                    bidValueShifted,
                    MAX_ITERATIONS_DLL_INSERTION,
                    hintGT
                );
                winners.remove(smallestVault);

                RevealedVault memory loser = revealedVaults[smallestVault];
                auction.clearBid(
                    loser.salt,
                    loser.bidder,
                    uint48(smallestBidValueShifted >> 160)
                );
            }
        }

        emit BidRevealed(
            auction.callback,
            vault,
            msg.sender,
            salt,
            bidValueWei
        );
    }

    function clearBid(
        Auction memory auction,
        uint96 salt,
        address bidder,
        uint48 bidValue
    ) internal {
        new SneakyMultiVault{salt: bytes32(uint256(salt))}(
            auction.callback,
            bidder,
            bidValue
        );
    }

    /// @notice Ends an active auction. Can only end an auction if the bid reveal
    ///         phase is over.
    /// @param bidder The winner of the auction.
    /// @param bid The amount bid by the winning bidder. In bid base units (1000 gwei).
    /// @param salt The salt used by the winning bidder.
    function clearWinningBid(
        Auction memory auction,
        DoubleLinkedList.List storage winners,
        address bidder,
        uint48 bid,
        uint96 salt
    ) external {
        if (block.timestamp <= auction.endOfRevealPeriod) {
            revert ISneakyAuctionErrors.RevealPeriodOngoingError();
        }

        // Verify that the given bidder is in fact winning by recomputing
        // the vault address and checking against the stored values.
        address vaultAddress = getVaultAddress(
            auction.callback,
            bidder,
            bid,
            salt
        );

        if (!winners.contains(vaultAddress)) {
            revert ISneakyAuctionErrors.NotWinningBidError();
        }

        // if (vaultAddress != highestBidVault) {
        //     revert ISneakyAuctionErrors.IncorrectVaultAddressError(highestBidVault, vaultAddress);
        // }
        // Transfer auctioned asset to highest bidder
        // ERC721(tokenContract).transferFrom(
        //     address(this),
        //     highestBidder,
        //     tokenId
        // );
        // Deploy vault to transfer ETH to seller, returning any excess to bidder
        auction.clearBid(salt, bidder, bid);
    }

    /// @notice Computes the `CREATE2` address of the `SneakyMultiVault` with the given
    ///         parameters. Note that the vault contract may not be deployed yet.
    /// @param bidder The address of the bidder.
    /// @param bidValue The amount bid. In bid base units (1000 gwei).
    /// @param salt The random input used to obfuscate the commitment.
    /// @return vault The address of the `SneakyMultiVault`.
    function getVaultAddress(
        IAuctionCallback callback,
        address bidder,
        uint48 bidValue,
        uint96 salt
    ) public view returns (address vault) {
        // Compute `CREATE2` address of vault
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xff),
                                address(this),
                                uint256(salt),
                                keccak256(
                                    abi.encodePacked(
                                        type(SneakyMultiVault).creationCode,
                                        abi.encode(callback, bidder, bidValue)
                                    )
                                )
                            )
                        )
                    )
                )
            );
    }
}
