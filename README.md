# Snappy-Code

Proof of Concept implementation of the Snappy Smart Contract from 

> Mavroudis, V., Wüst, K., Dhar, A., Kostiainen, K., & Capkun, S. Snappy: Fast On-chain Payments with Practical Collaterals. NDSS 2020

The code makes use of the BLS implementation from https://github.com/kfichter/solidity-bls/tree/master/contracts (BLS.sol & Pairing.sol) as well as the implementation of BN256G2 elliptic curve operations from https://github.com/musalbas/solidity-BN256G2 (BN256G2.sol).

The code is provided as is without any guarantees of correctness and should not be used directly in real-world deployments.
