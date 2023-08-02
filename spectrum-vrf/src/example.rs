mod tests {
    #[test]
    fn example() {
        use k256::Secp256k1;
        use sha2::Sha256;
        use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

        use crate::{vrf_gen, vrf_prove, vrf_verify};
        use crate::lottery::{get_lottery_threshold, proof_to_random_number};

        //Config the VRF:
        let vrf_range: u32 = 255;
        let constant_lead = "TEST"; //For the Leadership lottery.
        let constant_rnd = "RAND"; //For the Leadership lottery.
        let constant_sync = "SYNC"; //For the Time-Sync Beacon lottery.

        let stake: u64 = 10e12 as u64;
        let total_stake: u64 = 20e12 as u64;

        //Lets parameters for both lotteries:
        let leader_selection_fraction_num: u32 = 70;
        let sync_selection_fraction_num: u32 = 40;
        let selection_fraction_denom: u32 = 100;

        //Lottery message (concatenated seeds is included):
        let m_hash: Sha2Digest256 = sha256_hash("Lottery".as_bytes());

        //Generate VRF secret and private keys:
        let (vrf_sk, vrf_pk) =
            vrf_gen::<Secp256k1>().unwrap();

        //Get your lottery threshold:
        let thr_lead = get_lottery_threshold(vrf_range.clone(), stake, total_stake,
                                             leader_selection_fraction_num,
                                             selection_fraction_denom);
        let thr_sync = get_lottery_threshold(vrf_range.clone(), stake, total_stake,
                                             sync_selection_fraction_num,
                                             selection_fraction_denom);
        //Generate VRF proof:
        let proof =
            vrf_prove::<Sha256, Secp256k1>(vrf_sk, m_hash.clone()).unwrap();


        //Generate random numbers from the 'proof':
        println!("RESULTS:");
        println!("Leadership lottery:");
        let r_leadership = proof_to_random_number::<Sha256, Secp256k1>(&proof, constant_lead.as_bytes().to_vec(), vrf_range);
        if r_leadership < thr_lead {
            let r_rnd = proof_to_random_number::<Sha256, Secp256k1>(&proof, constant_rnd.as_bytes().to_vec(), vrf_range);

            println!("You are Leader!");
            println!("y_leadership: {:?}", r_leadership);
            println!("thr_lead: {:?}", thr_lead);
            println!("y_rnd: {:?}", r_rnd);
        } else { println!("Try again :("); }

        let r_sync = proof_to_random_number::<Sha256, Secp256k1>(&proof, constant_sync.as_bytes().to_vec(), vrf_range);

        println!("Time-Sync Lottery:");
        if r_sync < thr_sync {
            println!("You are the Time-Sync Beacon!");
            println!("y_sync: {:?}", r_sync);
            println!("thr_sync: {:?}", thr_sync);
        } else { println!("Try again :("); }

        //Verify the validity of the 'proof':
        let valid_proof =
            vrf_verify::<Sha256, Secp256k1>(vrf_pk, m_hash.clone(),
                                            proof).unwrap();
        assert!(valid_proof);
    }
}
