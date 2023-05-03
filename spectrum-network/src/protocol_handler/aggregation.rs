use std::collections::HashSet;

use futures::channel::oneshot::Sender;
use libp2p::PeerId;

use spectrum_crypto::digest::Digest256;

use crate::protocol_handler::sigma_aggregation::types::PublicKey;
use crate::protocol_handler::sigma_aggregation::Aggregated;

pub enum AggregationAction<H> {
    /// Restart aggregation with new committee.
    Reset {
        new_committee: HashSet<PublicKey>,
        new_message: Digest256<H>,
        channel: Sender<Result<Aggregated<H>, ()>>,
    },
}

pub trait Aggregation<H> {
    fn reset(&self, new_committee: HashSet<PeerId>, new_message: Digest256<H>);
}
