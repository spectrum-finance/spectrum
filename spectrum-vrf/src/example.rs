mod tests {
    use k256::Secp256k1;

    use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

    use crate::lottery::{get_lottery_threshold, proof_to_random_number};
    use crate::vrf::{vrf_gen, vrf_prove, vrf_verify};

    #[test]
    fn example() {
        //Config the VRF:
        let vrf_range: u32 = 255;
        let stake: u64 = 10e12 as u64;
        let total_stake: u64 = 20e12 as u64;
        let selection_fraction_num: u32 = 50;
        let selection_fraction_denom: u32 = 100;

        //Lottery message (concatenated seeds is included):
        let m_hash: Sha2Digest256 = sha256_hash("Lottery".as_bytes());

        //Generate VRF secret and private keys:
        let (vrf_sk, vrf_pk) =
            vrf_gen::<Secp256k1>().unwrap();

        //Generate VRF proof:
        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash.clone()).unwrap();

        //Verify the validity of the 'proof':
        let r = proof_to_random_number(&proof, vrf_range);

        //Generate random number from the 'proof':
        let valid_proof =
            vrf_verify::<Secp256k1>(vrf_pk, m_hash.clone(),
                                    proof).unwrap();
        assert!(valid_proof);

        //Get your lottery threshold:
        let thr = get_lottery_threshold(vrf_range.clone(), stake, total_stake,
                                        selection_fraction_num,
                                        selection_fraction_denom);
        //Lottery results:
        if r < thr {
            println!("You are winner!");
        } else { println!("Try again :("); }
    }
}
