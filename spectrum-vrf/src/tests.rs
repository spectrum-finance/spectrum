mod tests {
    use elliptic_curve::{Group, NonZeroScalar, ProjectivePoint, Scalar};
    use elliptic_curve::rand_core::OsRng;
    use k256::Secp256k1;

    use spectrum_crypto::digest::sha256_hash;
    use spectrum_crypto::digest::Sha2Digest256;

    use crate::vrf::{ECVRFProof, vrf_gen, vrf_prove, vrf_verify};

    #[test]
    fn normal_k256_eval() {
        let (vrf_sk, vrf_pk) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();
        let valid =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(), proof).unwrap();

        assert_eq!(valid, true);
    }

    #[test]
    fn wrong_public_key_k256_eval() {
        let (vrf_sk, _) =
            vrf_gen::<Secp256k1>().unwrap();
        let (_, pk_wrong) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();
        let valid =
            vrf_verify::<Secp256k1>(pk_wrong, m_hash.clone(), proof).unwrap();

        assert_eq!(valid, false);
    }

    #[test]
    fn wrong_secret_key_k256_eval() {
        let (_, vrf_pk) =
            vrf_gen::<Secp256k1>().unwrap();
        let (sk_wrong, _) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(sk_wrong, m_hash).unwrap();
        let valid =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(), proof).unwrap();

        assert_eq!(valid, false);
    }

    #[test]
    fn wrong_message_k256_eval() {
        let (vrf_sk, vrf_pk) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());
        let m_hash_wrong: Sha2Digest256 = sha256_hash("Test_wrong_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();
        let valid =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash_wrong, proof).unwrap();

        assert_eq!(valid, false);
    }

    #[test]
    fn wrong_proof_k256_eval() {
        let (vrf_sk, vrf_pk) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

        let random_scalar: Scalar<Secp256k1> = *NonZeroScalar::<Secp256k1>::random(&mut OsRng);
        let random_point = ProjectivePoint::<Secp256k1>::random(&mut OsRng);

        let proof_gamma_wrong = ECVRFProof::<Secp256k1> {
            gamma: random_point,
            c: random_scalar,
            s: proof.s,
        };
        let proof_c_wrong = ECVRFProof::<Secp256k1> {
            gamma: proof.gamma,
            c: random_scalar,
            s: proof.s,
        };
        let proof_s_wrong = ECVRFProof::<Secp256k1> {
            gamma: proof.gamma,
            c: proof.c,
            s: random_scalar,
        };


        let valid_gamma =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(),
                                    proof_gamma_wrong).unwrap();
        let valid_c =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(),
                                    proof_c_wrong).unwrap();
        let valid_s =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(),
                                    proof_s_wrong).unwrap();

        assert_eq!(valid_gamma, false);
        assert_eq!(valid_c, false);
        assert_eq!(valid_s, false);
    }
}