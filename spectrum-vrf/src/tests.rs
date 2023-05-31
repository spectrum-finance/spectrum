mod tests {
    use k256::Secp256k1;
    use spectrum_crypto::digest::Sha2Digest256;
    use spectrum_crypto::digest::sha256_hash;
    use crate::ECVRF;
    use crate::vrf::SpectrumVRF;

    #[test]
    fn normal_eval() {
        let (vrf_sk, vrf_pk) =
            SpectrumVRF::<Secp256k1>::gen().unwrap();
        let m_hash: Sha2Digest256 = sha256_hash(&[0xde, 0xad, 0xbe, 0xef]);
        let proof =
            SpectrumVRF::<Secp256k1>::prove(vrf_sk, m_hash).unwrap();
        let valid =
            SpectrumVRF::<Secp256k1>::verify(vrf_pk, m_hash, proof).unwrap();
        assert!(valid);
    }
}