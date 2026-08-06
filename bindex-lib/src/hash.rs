//! Hardware-accelerated SHA256 helpers.
//!
//! bitcoin_hashes 1.x ships runtime-detected hardware backends (aarch64
//! SHA2 extensions, x86 SHA-NI); the portable-only 0.14 line pinned by the
//! bitcoin-0.32 stack does not. Every digest bindex and its consumers
//! compute goes through this module, so the backend choice lives in one
//! place. Once the dependency tree moves to bitcoin 0.33+ (built on hashes
//! 1.x itself), this module dissolves into plain bitcoin_hashes calls.

use bitcoin::hashes::Hash as _;
use bitcoin_slices::{bsl, Parse};

use crate::index::Error;

/// Streaming SHA256: feed with [`HashEngine::input`], then [`finalize`].
pub type Engine = bitcoin_hashes::sha256::HashEngine;
pub use bitcoin_hashes::HashEngine;

/// Digest bytes of a streaming engine.
pub fn finalize(engine: Engine) -> [u8; 32] {
    HashEngine::finalize(engine).to_byte_array()
}

/// SHA256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    bitcoin_hashes::sha256::Hash::hash(bytes).to_byte_array()
}

/// Double-SHA256 (sha256d) of `bytes`.
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    bitcoin_hashes::sha256d::Hash::hash(bytes).to_byte_array()
}

/// Txid of a parsed transaction: double-SHA256 of its non-witness
/// serialization (BIP-141), assembled from the parser's preimage segments
/// without copying. The raw digest order matches the txid's internal byte
/// order, so the result is byte-identical to `Transaction::compute_txid()`.
pub fn txid_of(tx: &bsl::Transaction) -> bitcoin::Txid {
    let (a, b, c) = tx.txid_preimage();
    let digest = bitcoin_hashes::sha256d::Hash::hash_byte_chunks([a, b, c]);
    bitcoin::Txid::from_byte_array(digest.to_byte_array())
}

/// Txid of a consensus-serialized transaction.
pub fn txid(tx_bytes: &[u8]) -> Result<bitcoin::Txid, Error> {
    let res = bsl::Transaction::parse(tx_bytes).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    Ok(txid_of(res.parsed()))
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use hex_lit::hex;

    // block 1's coinbase (legacy 1-in/1-out transaction)
    const TX_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";

    #[test]
    fn test_txid_matches_bitcoin() {
        let tx_bytes = hex!(TX_HEX);
        let tx: bitcoin::Transaction = deserialize(&tx_bytes).unwrap();
        assert_eq!(super::txid(&tx_bytes).unwrap(), tx.compute_txid());
    }

    #[test]
    fn test_txid_strips_witness() {
        let tx_bytes = hex!(TX_HEX);
        let mut tx: bitcoin::Transaction = deserialize(&tx_bytes).unwrap();
        tx.input[0].witness.push([0xab; 42]);
        let segwit_bytes = serialize(&tx);
        assert_ne!(segwit_bytes.len(), tx_bytes.len());
        assert_eq!(super::txid(&segwit_bytes).unwrap(), tx.compute_txid());
    }

    #[test]
    fn test_digests_match_bitcoin() {
        let data = b"bindex hash test";
        assert_eq!(
            super::sha256(data),
            bitcoin::hashes::sha256::Hash::hash(data).to_byte_array()
        );
        assert_eq!(
            super::sha256d(data),
            bitcoin::hashes::sha256d::Hash::hash(data).to_byte_array()
        );
        let mut engine = super::Engine::default();
        super::HashEngine::input(&mut engine, data);
        assert_eq!(super::finalize(engine), super::sha256(data));
    }
}
