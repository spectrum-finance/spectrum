use std::sync::Arc;

use spectrum_ledger::ledger_view::history::HistoryReadAsync;
use spectrum_ledger::Height;

use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionSpec, HandshakeV1, SyncStatus,
};
use crate::types::ProtocolVer;

/// Peer chain in comparison to the local one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ChainCmp {
    Equal,
    Longer,
    Shorter,
    Fork(/*intersection_at*/ Option<Height>),
}

pub struct SyncState {
    height: Height,
    cmp: ChainCmp,
}

pub struct DiffusionService<THistory> {
    history: THistory,
}

impl<THistory> DiffusionService<THistory>
where
    THistory: HistoryReadAsync,
{
    pub async fn local_status(&self) -> SyncStatus {
        let tail = self.history.get_tail(256).await;
        SyncStatus {
            height: tail[0].height,
            last_blocks: tail.into_iter().map(|h| h.id).collect(),
        }
    }

    pub async fn make_poly_handshake(&self) -> Vec<(ProtocolVer, Option<DiffusionHandshake>)> {
        vec![(
            DiffusionSpec::v1(),
            Some(DiffusionHandshake::HandshakeV1(HandshakeV1(
                self.local_status().await,
            ))),
        )]
    }

    pub async fn remote_state(&self, peer_status: SyncStatus) -> SyncState {
        SyncState {
            height: peer_status.height,
            cmp: ChainCmp::Equal,
        }
    }
}
