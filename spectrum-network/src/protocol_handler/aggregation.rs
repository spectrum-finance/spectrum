use std::collections::{HashMap, HashSet};

use digest::{FixedOutput, HashMarker};
use futures::channel::oneshot::Sender;
use libp2p::{Multiaddr, PeerId};

use spectrum_crypto::digest::Digest;
use spectrum_crypto::pubkey::PublicKey;

use crate::protocol_handler::sigma_aggregation::Aggregated;

pub enum AggregationAction<H: HashMarker + FixedOutput> {
    /// Restart aggregation with new committee.
    Reset {
        new_committee: HashMap<PublicKey, Option<Multiaddr>>,
        new_message: Digest<H>,
        channel: Sender<Result<Aggregated<H>, ()>>,
    },
}

pub trait Aggregation<H: HashMarker + FixedOutput> {
    fn reset(&self, new_committee: HashSet<PeerId>, new_message: Digest<H>);
}
