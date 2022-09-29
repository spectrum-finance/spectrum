use crate::types::RawMessage;
use futures::{
    channel::mpsc,
    lock::{Mutex, MutexGuard},
    prelude::*,
};
use libp2p::PeerId;
use std::sync::Arc;

/// Sink connected directly to the node background task. Allows sending messages to the peer.
/// Can be cloned in order to obtain multiple references to the substream of the same peer.
#[derive(Debug, Clone)]
pub struct MessageSink {
    inner: Arc<MessageSinkIn>,
}

impl MessageSink {
    pub fn new(peer_id: PeerId, async_channel: mpsc::Sender<RawMessage>) -> Self {
        Self {
            inner: Arc::new(MessageSinkIn {
                peer_id,
                async_channel: Mutex::new(async_channel),
            }),
        }
    }
}

#[derive(Debug)]
struct MessageSinkIn {
    /// Target of the sink.
    peer_id: PeerId,
    /// Sender to use in asynchronous contexts. Uses an asynchronous mutex.
    async_channel: Mutex<mpsc::Sender<RawMessage>>,
}

impl MessageSink {
    /// Returns the [`PeerId`] the sink is connected to.
    pub fn peer_id(&self) -> &PeerId {
        &self.inner.peer_id
    }

    /// Wait until the remote is ready to accept a notification.
    ///
    /// Returns an error in the case where the connection is closed.
    ///
    /// The protocol name is expected to be checked ahead of calling this method. It is a logic
    /// error to send a notification using an unknown protocol.
    pub async fn reserve_notification(&self) -> Result<Ready<'_>, ()> {
        let mut lock = self.inner.async_channel.lock().await;

        let poll_ready = future::poll_fn(|cx| lock.poll_ready(cx)).await;
        if poll_ready.is_ok() {
            Ok(Ready { lock })
        } else {
            Err(())
        }
    }
}

/// Notification slot is reserved and the notification can actually be sent.
#[must_use]
#[derive(Debug)]
pub struct Ready<'a> {
    /// Guarded channel. The channel inside is guaranteed to not be full.
    lock: MutexGuard<'a, mpsc::Sender<RawMessage>>,
}

impl<'a> Ready<'a> {
    /// Consumes this slots reservation and actually queues the notification.
    ///
    /// Returns an error if the substream has been closed.
    pub fn send(mut self, notification: Vec<u8>) -> Result<(), ()> {
        self.lock
            .start_send(RawMessage::from(notification))
            .map_err(|_| ())
    }
}
