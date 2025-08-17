Target
https://github.com/OpenEdenHQ/openeden.vault.audit/tree/d18288e944df21729b18d430b2afec2da99b6287

 Vulnerability details
Overview
processWithdrawalQueue(uint _len) in OpenEdenVaultV4Impl can be forced to consume more gas than a single Ethereum block will allow, causing every queue–processing transaction to revert.

An attacker achieves this by flooding the withdrawalQueue with thousands of tiny withdrawal requests and letting the operator call processWithdrawalQueue(0) (“process all”). Funds stay safe, but all withdrawals—including the attacker’s—become indefinitely stuck (liveness / DoS risk).

Description
Affected contract / function
```solidity
function processWithdrawalQueue(uint _len) external onlyOperator {
    if (_len == 0) _len = withdrawalQueue.length();      // ← un‑bounded reset
    for (uint count; count < _len; ) {
        bytes memory data = withdrawalQueue.front();
        (address sender, address receiver,
         uint256 shares, bytes32 prevId) = _decodeData(data);

        uint256 assets = _convertToAssets(shares);
        if (assets > onchainAssets()) break;             // may exit early

        _withdraw(address(this), receiver, address(this), assets, shares);
        withdrawalQueue.popFront();                      // storage write
        unchecked { ++count; }
    }
}
```
When _len == 0 (the documented “process all” signal) the function sets _len to withdrawalQueue.length().
Each loop iteration:

Decodes (_decodeData) and performs KYC checks.
Transfers assets & fees (external safeTransfer calls).
Pops the queue item (SSTORE).
Gas cost ≈ 50 k–70 k per item. With ≳ 1 000 items the call exceeds the ~30 M gas block limit and reverts.

Because the revert happens after all work, the operator pays full gas yet no items are removed—future calls repeat the failure.

Recommendation
Implement any *one** (or combination) of the following:*

Bound _len
   if (_len == 0 || _len > MAX_BATCH) _len = MAX_BATCH; // e.g. MAX_BATCH = 50
Gas‑aware loop
   for (uint count; count < _len && gasleft() > 100_000; ) { ... }
Queue‑length guard in redeem()
   require(withdrawalQueue.length() < QUEUE_CAP, "queue full");
Any of these ensures a single call cannot exceed the block gas limit, restoring withdrawal liveness and eliminating the DoS vector.

 Validation steps
POC / Validation Steps
Queue flood – as any user, run:
   for (uint i = 0; i < 10_000; i++) {
       vault.redeem(1e6 /* tiny shares */, attacker); // pushes one queue item
   }
Operator call – maintainers execute their routine upkeep:
   vault.processWithdrawalQueue(0); // intends “process everything”
Observed result
Transaction uses > 30 M gas → out‑of‑gas revert.
No queue items are popped; length still 10 000.
Any subsequent call with _len == 0 (or large) fails the same way.
Honest users cannot withdraw until operators clear the queue manually in small batches or add strict bounds.
