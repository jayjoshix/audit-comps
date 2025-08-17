Summary
Pike Markets let users borrow any positive amount, even 1 wei. Without a floor, an attacker can spawn thousands of micro-loans that cost more gas to liquidate than they are worth. These positions linger, accrue interest, and can eventually crystallise as bad debt if prices move against the collateral.

Finding Description
The borrow flow (borrow() → borrowFresh() → RiskEngine.borrowAllowed()) never checks borrowAmount ≥ minBorrow. As a result:

A borrower with sufficient collateral can request 1 wei of USDC (or any asset).
The loan is recorded normally and accrues interest.
Liquidation rewards are percentage-based; for a 1 wei debt the reward is also 1 wei × (1 + incentive) ≪ gas fee.
Rational liquidators ignore the position until it grows, leaving dust loans outstanding for long periods.
Impact Explanation
High : Dust positions accumulate, bloating storage and bookkeeping.

Likelihood Explanation
Low: Attackers need to create thousands of dust positions.

Proof of Concept
function testMinimumBorrowVulnerability() public {
    address supplier  = makeAddr("supplier");
    address borrower  = makeAddr("borrower");

    /* 1 ░ seed USDC liquidity so a loan is possible */
    doDeposit(supplier, supplier, address(pUSDC), 1_000e6);

    /* 2 ░ borrower supplies WETH collateral and enters the market */
    doDepositAndEnter(borrower, borrower, address(pWETH), 1e18);

    /* 3 ░ attempt to borrow the minimum non-zero amount: 1 wei USDC */
    // EXPECTED BEHAVIOUR (after fix): revert with custom error.
    // CURRENT BEHAVIOUR (vulnerable): call succeeds — loan of 1 wei created.
    doBorrow(borrower, borrower, address(pUSDC), 1);

    /* 4 ░ sanity-check: borrower’s principal really is 1 wei */
    uint256 principal = pUSDC.borrowBalanceStored(borrower);
assertEq(principal, 1, "Market accepted dust loan  vuln present");
}
Recommendation
Implement a minimum borrow or deposit amount that ensures positions are always economically viable to liquidate.