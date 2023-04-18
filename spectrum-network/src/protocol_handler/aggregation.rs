use std::collections::HashSet;

use libp2p::PeerId;

use spectrum_crypto::digest::Digest256;

use crate::protocol_handler::sigma_aggregation::types::PublicKey;

pub enum AggregationAction<H> {
    /// Restart aggregation with new commetee.
    Reset {
        new_committee: HashSet<PublicKey>,
        new_message: Digest256<H>,
    },
}

pub trait Aggregation<H> {
    fn reset(&self, new_committee: HashSet<PeerId>, new_message: Digest256<H>);
}
