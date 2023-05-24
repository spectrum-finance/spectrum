use spectrum_ledger::block::BlockId;
use spectrum_ledger::ledger_view::history::HistoryReadAsync;
use spectrum_ledger::SlotNo;

use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionSpec, HandshakeV1, SyncStatus,
};
use crate::types::ProtocolVer;

/// Peer chain in comparison to the local one.
#[derive(Clone, PartialEq, Eq, Debug)]
enum RemoteChainCmp {
    Equal,
    Longer(/*wanted_suffix*/ Option<Vec<BlockId>>),
    Shorter(/*remote_best_slot*/ BlockId),
    Fork(/*intersection_at*/ Option<BlockId>),
    Nonsense,
}

pub struct SyncState {
    height: SlotNo,
    cmp: RemoteChainCmp,
}

pub struct DiffusionService<THistory> {
    history: THistory,
}

const SYNC_HEADERS: usize = 256;

impl<THistory> DiffusionService<THistory>
where
    THistory: HistoryReadAsync,
{
    pub async fn local_status(&self) -> SyncStatus {
        let tail = self.history.get_tail(SYNC_HEADERS).await;
        SyncStatus {
            height: tail.last().slot,
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
            cmp: self.compare_remote(peer_status).await,
        }
    }

    /// Compare remote chain with the local one.
    async fn compare_remote(&self, peer_status: SyncStatus) -> RemoteChainCmp {
        let local_tip = self.history.get_tip().await;
        let peer_height = peer_status.height;
        let peer_tail = peer_status
            .last_blocks
            .into_iter()
            .enumerate()
            .map(|(i, blk)| (SlotNo::from(<u64>::from(peer_height) - i as u64), blk))
            .collect::<Vec<_>>();

        if peer_tail.is_empty() {
            RemoteChainCmp::Shorter(BlockId::ORIGIN)
        } else {
            let delta = <u64>::from(peer_height - local_tip.slot);
            let num_shared_blocks = peer_tail.len() as u64;
            if delta > num_shared_blocks {
                RemoteChainCmp::Longer(None)
            } else {
                // Trying to find common point using only the tip of our local chain
                let mut optimistic_common_point = None;
                for (sl, blk) in &peer_tail {
                    if *sl == local_tip.slot {
                        if *blk == local_tip.id {
                            optimistic_common_point = Some(*sl);
                        } else {
                            break;
                        }
                    }
                }
                match optimistic_common_point {
                    Some(common_sl) if peer_height >= local_tip.slot =>
                    // Equal | Longer(Some(wanted_suffix))
                    {
                        if common_sl == peer_height {
                            RemoteChainCmp::Equal
                        } else {
                            let wanted_suffix = peer_tail
                                .into_iter()
                                .take_while(|(sl, _)| *sl >= common_sl)
                                .map(|(_, blk)| blk)
                                .collect();
                            RemoteChainCmp::Longer(Some(wanted_suffix))
                        }
                    }
                    None => {
                        if let Some(common_point) = self
                            .common_point(peer_tail.iter().map(|(_, blk)| blk).collect())
                            .await
                        {
                            let peer_tip = peer_tail[0].1;
                            if common_point == peer_tip {
                                RemoteChainCmp::Shorter(common_point)
                            } else {
                                RemoteChainCmp::Fork(Some(common_point))
                            }
                        } else {
                            RemoteChainCmp::Fork(None)
                        }
                    }
                    _ => RemoteChainCmp::Nonsense,
                }
            }
        }
    }

    /// Find the point where remote chain intersects local one.
    async fn common_point(&self, remote_tail: Vec<&BlockId>) -> Option<BlockId> {
        for blk in remote_tail {
            if self.history.member(blk).await {
                return Some(blk.clone());
            }
        }
        None
    }
}
