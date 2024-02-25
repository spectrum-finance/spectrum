#[cfg(test)]
mod test {
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use k256::Secp256k1;
    use sha2::Sha256;

    use spectrum_crypto::digest::{blake2b256_hash, sha256_hash, Blake2b256, Digest};
    use spectrum_vrf::utils::key_pair_gen;

    use crate::composition_utils::calculate_scheme_pk_from_signature;
    use crate::{kes_gen, kes_sign, kes_update, kes_verify};

    #[test]
    fn kes_gen_test() {
        let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (_, pk) = key_pair_gen(&seed_0);
        let (_, pk_00) = kes_gen::<Sha256, Secp256k1>(&0, &seed_0).unwrap();

        assert_eq!(pk_00, pk);

        for merkle_tree_high in 0..10 {
            let seed_1 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

            let (_, pk_0) = kes_gen::<Sha256, Secp256k1>(&merkle_tree_high, &seed_1).unwrap();
            let (_, pk_1) = kes_gen::<Sha256, Secp256k1>(&merkle_tree_high, &seed_1).unwrap();
            let (_, pk_2) = kes_gen::<Sha256, Secp256k1>(&merkle_tree_high, &seed_0).unwrap();

            assert_eq!(pk_0, pk_1);
            assert_ne!(pk_0, pk_2);
        }
    }

    #[test]
    fn kes_update_test() {
        // Test to check assertions inside the kes_update()
        for merkle_tree_high in 0..10 {
            let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

            let (mut secret, _) = kes_gen::<Sha256, Secp256k1>(&merkle_tree_high, &seed_0).unwrap();

            for _ in 0..(2 as u32).pow(merkle_tree_high) - 1 {
                secret = kes_update::<Sha256, Secp256k1>(secret).unwrap();
            }
        }
    }

    #[test]
    fn kes_sign_test() {
        let m_fair_hash: Digest<Sha256> = sha256_hash("Hi".as_bytes());
        let m_mal_hash: Digest<Sha256> = sha256_hash("Buy".as_bytes());

        for merkle_tree_high in 0..10 {
            let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
            let (mut secret, pk_0) = kes_gen::<Sha256, Secp256k1>(&merkle_tree_high, &seed_0).unwrap();

            for i in 0..(2 as u32).pow(merkle_tree_high) - 1 {
                let sig_00 = kes_sign::<Sha256, Secp256k1>(&m_fair_hash, &secret, &i).unwrap();
                let sig_01 = kes_sign::<Sha256, Secp256k1>(&m_mal_hash, &secret, &i).unwrap();
                secret = kes_update::<Sha256, Secp256k1>(secret).unwrap();
                let sig_1 = kes_sign::<Sha256, Secp256k1>(&m_fair_hash, &secret, &(i + 1)).unwrap();
                assert_ne!(sig_00.sig, sig_01.sig);
                assert_ne!(sig_00.sig, sig_1.sig);
                assert_ne!(sig_00.hot_pk, sig_1.hot_pk);
                assert_eq!(
                    calculate_scheme_pk_from_signature::<Sha256, Secp256k1>(&sig_00, &i),
                    pk_0
                );
                assert_ne!(
                    calculate_scheme_pk_from_signature::<Sha256, Secp256k1>(&sig_01, &(i + 1)),
                    pk_0
                );
                assert_eq!(
                    calculate_scheme_pk_from_signature::<Sha256, Secp256k1>(&sig_1, &(i + 1)),
                    pk_0
                );
            }
        }
    }

    #[test]
    fn kes_verify_test_sha2() {
        let m_fair_hash: Digest<Sha256> = sha256_hash("Hi".as_bytes());
        let m_mal_hash: Digest<Sha256> = sha256_hash("Buy".as_bytes());

        for merkle_tree_high in 0..10 {
            let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
            let (mut secret, pk_0) = kes_gen::<Sha256, Secp256k1>(&merkle_tree_high, &seed_0).unwrap();

            for i in 0..(2 as u32).pow(merkle_tree_high) - 1 {
                let sig_00 = kes_sign::<Sha256, Secp256k1>(&m_fair_hash, &secret, &i).unwrap();
                let sig_01 = kes_sign::<Sha256, Secp256k1>(&m_mal_hash, &secret, &i).unwrap();
                secret = kes_update::<Sha256, Secp256k1>(secret).unwrap();
                let sig_1 = kes_sign::<Sha256, Secp256k1>(&m_fair_hash, &secret, &i).unwrap();

                let ver_fair_00 = kes_verify::<Sha256, Secp256k1>(&sig_00, &m_fair_hash, &pk_0, &i).unwrap();
                let ver_mal_period_00 =
                    kes_verify::<Sha256, Secp256k1>(&sig_00, &m_fair_hash, &pk_0, &(i + 1)).unwrap();
                let ver_mal_message_00 =
                    kes_verify::<Sha256, Secp256k1>(&sig_00, &m_mal_hash, &pk_0, &i).unwrap();
                let ver_mal_signature_00 =
                    kes_verify::<Sha256, Secp256k1>(&sig_01, &m_fair_hash, &pk_0, &i).unwrap();
                let ver_mal_secret_00 =
                    kes_verify::<Sha256, Secp256k1>(&sig_1, &m_fair_hash, &pk_0, &i).unwrap();

                assert!(ver_fair_00);
                assert!(!!!ver_mal_period_00);
                assert!(!!!ver_mal_message_00);
                assert!(!!!ver_mal_signature_00);
                assert!(!!!ver_mal_secret_00);
            }
        }
    }

    #[test]
    fn kes_verify_test_blake2b() {
        let m_fair_hash: Digest<Blake2b256> = blake2b256_hash("ABC".as_bytes());
        let m_mal_hash: Digest<Blake2b256> = blake2b256_hash("CBD".as_bytes());

        for merkle_tree_high in 0..10 {
            let seed_0 = blake2b256_hash(OsRng.next_u64().to_string().as_bytes());
            let (mut secret, pk_0) = kes_gen::<Blake2b256, Secp256k1>(&merkle_tree_high, &seed_0).unwrap();

            for i in 0..(2 as u32).pow(merkle_tree_high) - 1 {
                let sig_00 = kes_sign::<Blake2b256, Secp256k1>(&m_fair_hash, &secret, &i).unwrap();
                let sig_01 = kes_sign::<Blake2b256, Secp256k1>(&m_mal_hash, &secret, &i).unwrap();
                secret = kes_update::<Blake2b256, Secp256k1>(secret).unwrap();
                let sig_1 = kes_sign::<Blake2b256, Secp256k1>(&m_fair_hash, &secret, &i).unwrap();

                let ver_fair_00 =
                    kes_verify::<Blake2b256, Secp256k1>(&sig_00, &m_fair_hash, &pk_0, &i).unwrap();
                let ver_mal_period_00 =
                    kes_verify::<Blake2b256, Secp256k1>(&sig_00, &m_fair_hash, &pk_0, &(i + 1)).unwrap();
                let ver_mal_message_00 =
                    kes_verify::<Blake2b256, Secp256k1>(&sig_00, &m_mal_hash, &pk_0, &i).unwrap();
                let ver_mal_signature_00 =
                    kes_verify::<Blake2b256, Secp256k1>(&sig_01, &m_fair_hash, &pk_0, &i).unwrap();
                let ver_mal_secret_00 =
                    kes_verify::<Blake2b256, Secp256k1>(&sig_1, &m_fair_hash, &pk_0, &i).unwrap();

                assert!(ver_fair_00);
                assert!(!!!ver_mal_period_00);
                assert!(!!!ver_mal_message_00);
                assert!(!!!ver_mal_signature_00);
                assert!(!!!ver_mal_secret_00);
            }
        }
    }
}
