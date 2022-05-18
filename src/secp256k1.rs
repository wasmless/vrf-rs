use crate::ECCVRF;
use anyhow::{anyhow, Result};

use k256::{
    elliptic_curve::bigint::{ArrayEncoding, ByteArray, Encoding},
    elliptic_curve::group::GroupEncoding,
    elliptic_curve::Curve,
    elliptic_curve::ScalarCore,
    AffinePoint, CompressedPoint, ProjectivePoint, PublicKey, Scalar, Secp256k1, SecretKey,
};
use sha2::{digest::Digest, digest::FixedOutput, Sha256};

pub struct Secp256k1VRF {
    q_len: usize,
    c_len: usize,
    pt_len: usize,
}

impl ECCVRF for Secp256k1VRF {
    fn prove(&self, sk: &[u8], alpha_string: &[u8]) -> Result<Vec<u8>> {
        let sk = SecretKey::from_be_bytes(sk)?;

        let pk = sk.public_key();

        let pk = pk.as_affine();

        let h = Self::encode_to_curve(pk.clone(), alpha_string)?;

        let h_string = Self::point_to_string(h);

        let gramma = (h * sk.to_nonzero_scalar().as_ref()).to_affine();

        let mut hasher = Sha256::default();

        hasher.update(&h_string);

        let k = Self::nonce_generation(&sk, hasher.finalize_fixed());

        let u = (ProjectivePoint::GENERATOR * k).to_affine();
        let v = (h * k).to_affine();

        let c = self.challenge_generation(pk.clone(), h, gramma, u, v);

        let s = Self::compute_s(
            k.into(),
            c,
            sk.to_nonzero_scalar().as_ref(),
            Secp256k1::ORDER,
        );

        return Ok([
            &Self::point_to_string(gramma)[..],
            &Self::int_to_string(c, self.c_len)?[..],
            &Self::int_to_string(s, self.q_len)?[..],
        ]
        .concat());
    }

    fn verify(&self, pk: &[u8], alpha_string: &[u8], pi_string: &[u8]) -> Result<()> {
        let y = PublicKey::from_sec1_bytes(pk)?;

        let pk = y.as_affine();

        let (gramma, c, s) = self.decode_proof(pi_string)?;

        let s_scalar = Self::int_to_scalar(s);

        let c_scalar = Self::int_to_scalar(c);

        let h = Self::encode_to_curve(pk.clone(), alpha_string)?;

        let u = (ProjectivePoint::GENERATOR * s_scalar - pk.clone() * c_scalar).to_affine();

        let v = (h * s_scalar - gramma * c_scalar).to_affine();

        let c1 = self.challenge_generation(pk.clone(), h, gramma, u, v);

        if c1 != c {
            Err(anyhow!("Invalid"))
        } else {
            Ok(())
        }
    }

    fn proof_to_hash(&self, pi_string: &[u8]) -> Result<Vec<u8>> {
        let (gramma, _, _) = self.decode_proof(pi_string)?;

        let mut hasher = Sha256::default();

        hasher.update([&[0xfe, 0x03], &Self::point_to_string(gramma)[..], &[0x00]].concat());

        Ok(hasher.finalize_fixed().to_vec())
    }
}

impl Secp256k1VRF {
    fn int_to_scalar(i: k256::U256) -> Scalar {
        Scalar::from(ScalarCore::new(i).unwrap())
    }

    fn decode_proof(&self, pi_string: &[u8]) -> Result<(AffinePoint, k256::U256, k256::U256)> {
        if pi_string.len() != self.pt_len + self.c_len + self.q_len {
            return Err(anyhow!("invalid pi_string"));
        }

        let gramma = Self::string_to_point(&pi_string[0..self.pt_len])?;

        let c = self.string_padding_to_int(&pi_string[self.pt_len..(self.c_len + self.pt_len)]);

        let s = self.string_padding_to_int(&pi_string[(self.c_len + self.pt_len)..]);

        Ok((gramma, c, s))
    }

    pub fn new() -> Self {
        let q_len = k256::U256::BYTE_SIZE;

        let c_len = ((q_len + (q_len % 2)) / 2) as usize;

        let pt_len = q_len + 1;

        Secp256k1VRF {
            q_len,
            c_len,
            pt_len,
        }
    }

    fn compute_s(k: k256::U256, c: k256::U256, x: &k256::Scalar, q: k256::U256) -> k256::U256 {
        let c = Self::int_to_scalar(c) * x;

        k.add_mod(&c.into(), &q)
    }

    fn point_to_string(point: AffinePoint) -> CompressedPoint {
        point.to_bytes()
    }

    fn encode_to_curve(pk: AffinePoint, alpha_string: &[u8]) -> Result<AffinePoint> {
        let mut hash_string = [
            &[0xfe, 0x01],
            &Self::point_to_string(pk)[..],
            &alpha_string[..],
            &[0x00, 0x00],
        ]
        .concat();

        let ctr_string_pos = hash_string.len() - 2;

        for ctr in 0..255 {
            hash_string[ctr_string_pos] = ctr;

            let mut hasher = Sha256::default();

            hasher.update(&hash_string);

            let data = hasher.finalize_fixed();

            let mut v = vec![0x02];
            v.extend(&data);

            match Self::string_to_point(&v) {
                Ok(point) => return Ok(point),
                Err(_) => continue,
            }
        }

        Err(anyhow!("Not found valid point"))
    }

    fn string_to_point(data: &[u8]) -> Result<AffinePoint> {
        let mut encoding = CompressedPoint::default();

        encoding.copy_from_slice(data);

        // let point: Option<C::ProjectivePoint> = C::ProjectivePoint::from_bytes(&encoding).into();

        match AffinePoint::from_bytes(&encoding).into() {
            Some(point) => Ok(point),
            None => Err(anyhow!("Not found")),
        }
    }

    fn nonce_generation(sk: &SecretKey, h_string: ByteArray<k256::U256>) -> Scalar {
        let x = sk.as_scalar_core().as_uint();

        let k = rfc6979::generate_k::<Sha256, k256::U256>(x, &Secp256k1::ORDER, &h_string, &[0; 0]);

        Scalar::from(ScalarCore::new(*k).unwrap())
    }

    fn challenge_generation(
        &self,
        y: AffinePoint,
        h: AffinePoint,
        gramma: AffinePoint,
        u: AffinePoint,
        v: AffinePoint,
    ) -> k256::U256 {
        // let k_b = (ProjectivePoint::GENERATOR * k).to_affine();
        // let k_h = (h * k).to_affine();

        let str: Vec<u8> = [
            &[0xfe, 0x02],
            &Self::point_to_string(y)[..],
            &Self::point_to_string(h)[..],
            &Self::point_to_string(gramma)[..],
            &Self::point_to_string(u)[..],
            &Self::point_to_string(v)[..],
            &[0x00],
        ]
        .concat();

        let mut hasher = Sha256::default();

        hasher.update(&str);

        let c_string = hasher.finalize_fixed();

        self.string_padding_to_int(&c_string[0..self.c_len])
    }

    pub fn string_padding_to_int(&self, data: &[u8]) -> k256::U256 {
        Self::string_to_int(
            ByteArray::<k256::U256>::from_slice(&Self::padding_zero(data, self.q_len)).clone(),
        )
    }

    fn padding_zero(data: &[u8], len: usize) -> Vec<u8> {
        if data.len() >= len {
            return data[0..len].to_vec();
        }

        [&vec![0; len - data.len()][..], data].concat()
    }

    fn string_to_int(data: ByteArray<k256::U256>) -> k256::U256 {
        k256::U256::from_be_byte_array(data)
    }

    fn int_to_string(a: k256::U256, len: usize) -> Result<Vec<u8>> {
        let mut bytes = a.to_be_byte_array().to_vec();

        if bytes.len() > len {
            return Ok(bytes[bytes.len() - len..].to_vec());
        }

        if bytes.len() < len {
            bytes = [&vec![0; len - bytes.len()][..], &bytes].concat();
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::ECCVRF;

    use super::Secp256k1VRF;
    use anyhow::Result;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::SecretKey;

    #[test]
    fn test_prove() -> Result<()> {
        let sk = SecretKey::from_jwk_str(
            r#"{"kty":"EC","crv":"secp256k1","x":"Q68PFILOdy9-n2dYE890d0kyCRbhkRGvNneqcMXQYz0","y":"yaeV9Con3FqdI9sMIxWeL7VybppotYK6Aldh0d7Li4Y","d":"U60R3jML_1lVAf8fSfGAcbzwEVOflIjwvYtDZyme6uU"}"#,
        )?;

        let vrf = Secp256k1VRF::new();

        let alpha_string = b"hello world~~~~";

        let pi_string = vrf.prove(&sk.to_be_bytes().to_vec(), alpha_string)?;

        let pk = sk.public_key().as_affine().to_bytes();

        vrf.verify(&pk, alpha_string, &pi_string)?;

        let hash = vrf.proof_to_hash(&pi_string)?;

        println!(
            "hash({}) pi({}) pk({})",
            hex::encode(hash.clone()),
            hex::encode(pi_string),
            hex::encode(pk),
        );

        Ok(())
    }

    #[test]
    fn test_add_mod() {
        let a = k256::U256::from_u32(1);
        let b = k256::U256::from_u32(4);
        let q = k256::U256::from_u32(3);

        assert_eq!(a.add_mod(&b, &q), k256::U256::from_u32(2));
    }
}
