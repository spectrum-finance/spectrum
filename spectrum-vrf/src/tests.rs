mod tests {
    use bigint::U256;
    use elliptic_curve::rand_core::OsRng;
    use elliptic_curve::{Group, NonZeroScalar, ProjectivePoint, Scalar};
    use k256::Secp256k1;

    use spectrum_crypto::digest::sha256_hash;
    use spectrum_crypto::digest::Sha2Digest256;

    use crate::lottery::{get_lottery_threshold, proof_to_random_number};
    use crate::vrf::{vrf_gen, vrf_prove, vrf_verify, ECVRFProof};

    #[test]
    fn normal_k256_eval() {
        let (vrf_sk, vrf_pk) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();
        let valid = vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(), proof).unwrap();

        assert!(valid);
    }

    #[test]
    fn wrong_public_key_k256_eval() {
        let (vrf_sk, _) = vrf_gen::<Secp256k1>().unwrap();
        let (_, pk_wrong) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();
        let valid = vrf_verify::<Secp256k1>(pk_wrong, m_hash.clone(), proof).unwrap();

        assert!(!!!valid);
    }

    #[test]
    fn wrong_secret_key_k256_eval() {
        let (_, vrf_pk) = vrf_gen::<Secp256k1>().unwrap();
        let (sk_wrong, _) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof = vrf_prove::<Secp256k1>(sk_wrong, m_hash).unwrap();
        let valid = vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(), proof).unwrap();

        assert!(!!!valid);
    }

    #[test]
    fn wrong_message_k256_eval() {
        let (vrf_sk, vrf_pk) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());
        let m_hash_wrong: Sha2Digest256 = sha256_hash("Test_wrong_tx".as_bytes());

        let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();
        let valid = vrf_verify::<Secp256k1>(vrf_pk, m_hash_wrong, proof).unwrap();

        assert!(!!!valid);
    }

    #[test]
    fn wrong_proof_k256_eval() {
        let (vrf_sk, vrf_pk) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

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

        let valid_gamma = vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(), proof_gamma_wrong).unwrap();
        let valid_c = vrf_verify::<Secp256k1>(vrf_pk.clone(), m_hash.clone(), proof_c_wrong).unwrap();
        let valid_s = vrf_verify::<Secp256k1>(vrf_pk.clone(), m_hash.clone(), proof_s_wrong).unwrap();

        assert!(!!!valid_gamma);
        assert!(!!!valid_c);
        assert!(!!!valid_s);
    }

    #[test]
    fn proof_to_random_number_test() {
        let base_vrf_range = 64;
        let option_vrf_range = 128;

        let (vrf_sk, _) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

        let r_0 = proof_to_random_number(&proof, base_vrf_range);
        let r_1 = proof_to_random_number(&proof, base_vrf_range.clone());
        let r_2 = proof_to_random_number(&proof, option_vrf_range.clone());

        let valid_order = r_1 < r_2;

        assert_eq!(r_0, r_1);
        assert!(valid_order);
    }

    #[test]
    fn random_distribution_test() {
        let vrf_range: u32 = 16;

        let m_hash: Sha2Digest256 = sha256_hash("Lottery".as_bytes());

        let mut r_array = Vec::new();
        let n_iters = 1000;
        for _ in 0..n_iters {
            let (vrf_sk, _) = vrf_gen::<Secp256k1>().unwrap();

            let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash.clone()).unwrap();

            let r = proof_to_random_number(&proof, vrf_range);

            r_array.push(r.as_u64());
        }
        r_array.sort();

        let total_average = (r_array.iter().sum::<u64>() as i64) / n_iters as i64;
        let first_half_avg: i64 = r_array[0..n_iters / 2].iter().sum::<u64>() as i64 / (n_iters / 2) as i64;
        let second_half_avg: i64 =
            r_array[n_iters / 2..n_iters].iter().sum::<u64>() as i64 / (n_iters / 2) as i64;

        assert!((total_average / 2 - first_half_avg).abs() as f64 / total_average as f64 <= 0.05);
        assert!((total_average * 3 / 2 - second_half_avg).abs() as f64 / total_average as f64 <= 0.05);
    }

    #[test]
    fn get_lottery_threshold_test() {
        let vrf_range: u32 = 128;
        let stake: u64 = 10e12 as u64;
        let stake_1: u64 = 5e12 as u64;
        let total_stake: u64 = 10e12 as u64;
        let selection_fraction_num: u32 = 100;
        let selection_fraction_denom: u32 = 100;

        let thr_0 = get_lottery_threshold(
            vrf_range,
            stake,
            total_stake,
            selection_fraction_num,
            selection_fraction_denom,
        );

        let thr_1 = get_lottery_threshold(
            vrf_range,
            stake_1,
            total_stake.clone(),
            selection_fraction_num.clone(),
            selection_fraction_denom.clone(),
        );

        let mult = U256::from(2).pow(U256::from(vrf_range));

        assert_eq!(thr_0, thr_1);
        assert_eq!(thr_0, mult)
    }

    #[test]
    fn lottery_threshold_rounding_test() {
        let vrf_range: u32 = 255;
        let stake_0: u64 = 10e16 as u64;
        let stake_1: u64 = 11e16 as u64;
        let total_stake: u64 = stake_0 + stake_1;
        let selection_fraction_num: u32 = 10;
        let selection_fraction_denom: u32 = 100;

        let thr_0 = get_lottery_threshold(
            vrf_range,
            stake_0,
            total_stake,
            selection_fraction_num,
            selection_fraction_denom,
        );

        let thr_1 = get_lottery_threshold(
            vrf_range.clone(),
            stake_1,
            total_stake.clone(),
            selection_fraction_num.clone(),
            selection_fraction_denom.clone(),
        );

        assert!(thr_0 < thr_1);
    }

    #[test]
    fn lottery_bounds_test() {
        let vrf_range: u32 = 255;
        let stake: u64 = 10e12 as u64;
        let total_stake: u64 = stake.clone();
        let selection_fraction_num_0: u32 = 100;
        let selection_fraction_num_1: u32 = 0;
        let selection_fraction_denom: u32 = 100;

        let (vrf_sk, _) = vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Lottery".as_bytes());

        let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

        let r = proof_to_random_number(&proof, vrf_range);

        let thr_0 = get_lottery_threshold(
            vrf_range,
            stake,
            total_stake,
            selection_fraction_num_0,
            selection_fraction_denom,
        );

        let thr_1 = get_lottery_threshold(
            vrf_range.clone(),
            stake.clone(),
            total_stake.clone(),
            selection_fraction_num_1,
            selection_fraction_denom.clone(),
        );

        assert!(r < thr_0);
        assert!(r > thr_1);
    }

    #[test]
    fn lottery_fraction_count_test() {
        let vrf_range: u32 = 255;
        let stake: u64 = 10e12 as u64;
        let total_stake: u64 = 10e12 as u64;
        let selection_fraction_num: u32 = 23;
        let selection_fraction_denom: u32 = 100;

        let m_hash: Sha2Digest256 = sha256_hash("Lottery".as_bytes());

        let mut wins = 0;
        let n_iters = 1000;
        for _ in 0..n_iters {
            let (vrf_sk, _) = vrf_gen::<Secp256k1>().unwrap();

            let proof = vrf_prove::<Secp256k1>(vrf_sk, m_hash.clone()).unwrap();

            let r = proof_to_random_number(&proof, vrf_range);

            let thr = get_lottery_threshold(
                vrf_range,
                stake,
                total_stake,
                selection_fraction_num,
                selection_fraction_denom,
            );

            if r < thr {
                wins += 1
            }
        }

        assert!(
            (wins as f32 / n_iters as f32 - selection_fraction_num as f32 / selection_fraction_denom as f32)
                .abs()
                <= 0.05
        )
    }
}
