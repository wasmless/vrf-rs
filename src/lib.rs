pub mod secp256k1;

use anyhow::Result;

pub trait ECCVRF {
    fn prove(&self, sk: &[u8], alpha_string: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, pk: &[u8], alpha_string: &[u8], pi_string: &[u8]) -> Result<()>;
    fn proof_to_hash(&self, pi_string: &[u8]) -> Result<Vec<u8>>;
}

/// Create new ECCVRF context, default ciphersuites is (secp256k1-Keccak256)
pub fn new() -> impl ECCVRF {
    secp256k1::Secp256k1VRF::new()
}
