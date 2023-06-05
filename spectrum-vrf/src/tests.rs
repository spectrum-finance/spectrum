mod tests {
    use elliptic_curve::{Group, NonZeroScalar, ProjectivePoint, Scalar};
    use elliptic_curve::rand_core::OsRng;
    use k256::Secp256k1;
    use bigint::U256;

    use spectrum_crypto::digest::sha256_hash;
    use spectrum_crypto::digest::Sha2Digest256;

    use crate::lottery::{proof_to_random_number, get_lottery_threshold};
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

        assert!(valid);
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

        assert!(!!!valid);
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

        assert!(!!!valid);
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

        assert!(!!!valid);
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
            vrf_verify::<Secp256k1>(vrf_pk.clone(), m_hash.clone(),
                                    proof_c_wrong).unwrap();
        let valid_s =
            vrf_verify::<Secp256k1>(vrf_pk.clone(), m_hash.clone(),
                                    proof_s_wrong).unwrap();

        assert!(!!!valid_gamma);
        assert!(!!!valid_c);
        assert!(!!!valid_s);
    }

    #[test]
    fn proof_to_random_number_test() {
        let base_vrf_range = 10;
        let option_vrf_range = 16;

        let (vrf_sk, _) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

        let r_0 = proof_to_random_number(&proof, base_vrf_range);
        let r_1 = proof_to_random_number(&proof, base_vrf_range.clone());
        let r_2 = proof_to_random_number(&proof, option_vrf_range.clone());

        let valid_order = r_1 < r_2;

        assert_eq!(r_0, r_1);
        assert!(valid_order);
    }

    #[test]
    fn get_lottery_threshold_test() {
        let vrf_range: u32 = 16;
        let stake: u64 = 100000000;
        let stake_1: u64 = 50000000;
        let total_stake: u64 = 100000000;
        let selection_fraction_num: u32 = 100;
        let selection_fraction_denom: u32 = 100;

        let thr_0 = get_lottery_threshold(vrf_range, stake, total_stake,
                                          selection_fraction_num,
                                          selection_fraction_denom);

        let thr_1 = get_lottery_threshold(vrf_range, stake_1,
                                          total_stake.clone(),
                                          selection_fraction_num.clone(),
                                          selection_fraction_denom.clone());

        let mult = U256::try_from(2_i32.pow(vrf_range) as u64).unwrap();

        assert_eq!(thr_0, thr_1);
        assert_eq!(thr_0, mult)
    }

    #[test]
    fn lottery_bounds_test() {
        let vrf_range: u32 = 16;
        let stake: u64 = 100000000;
        let total_stake: u64 = 100000000;
        let selection_fraction_num_0: u32 = 100;
        let selection_fraction_num_1: u32 = 0;
        let selection_fraction_denom: u32 = 100;

        let (vrf_sk, _) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Lottery".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

        let r = proof_to_random_number(&proof, vrf_range);

        let thr_0 = get_lottery_threshold(vrf_range, stake, total_stake,
                                          selection_fraction_num_0,
                                          selection_fraction_denom);

        let thr_1 = get_lottery_threshold(vrf_range.clone(), stake.clone(),
                                          total_stake.clone(),
                                          selection_fraction_num_1,
                                          selection_fraction_denom.clone());
        assert!(r < thr_0);
        assert!(r > thr_1);
        println!("{:?}", r);
        println!("{:?}", thr_0);
        println!("{:?}", thr_1);

    }
}