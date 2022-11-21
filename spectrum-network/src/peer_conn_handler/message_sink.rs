use crate::types::RawMessage;
use futures::{
    channel::mpsc,
    lock::{Mutex as AsyncMutex, MutexGuard},
    prelude::*,
};
use libp2p::PeerId;
use std::sync::{Arc, Mutex};

/// Sink connected directly to the node background task. Allows sending messages to the peer.
/// Can be cloned in order to obtain multiple references to the substream of the same peer.
#[derive(Debug, Clone)]
pub struct MessageSink {
    inner: Arc<MessageSinkIn>,
}

impl MessageSink {
    pub fn new(
        peer_id: PeerId,
        async_channel: mpsc::Sender<StreamNotification>,
        sync_channel: mpsc::Sender<StreamNotification>,
    ) -> Self {
        Self {
            inner: Arc::new(MessageSinkIn {
                peer_id,
                async_channel: AsyncMutex::new(async_channel),
                sync_channel: Mutex::new(Some(sync_channel)),
            }),
        }
    }
}

#[derive(Debug)]
pub enum StreamNotification {
    Message(RawMessage),
    ForceClose,
}

#[derive(Debug)]
struct MessageSinkIn {
    /// Target of the sink.
    peer_id: PeerId,
    /// Sender to use in asynchronous contexts. Uses an asynchronous mutex.
    async_channel: AsyncMutex<mpsc::Sender<StreamNotification>>,
    /// Sender to use in synchronous contexts. Uses an synchronous mutex.
    sync_channel: Mutex<Option<mpsc::Sender<StreamNotification>>>,
}

impl MessageSink {
    /// Returns the [`PeerId`] the sink is connected to.
    pub fn peer_id(&self) -> &PeerId {
        &self.inner.peer_id
    }

    /// Sends a message to the peer.
    ///
    /// If the buffer is exhausted, the channel will be closed
    /// via `SyncNotification::ForceClose` directive.
    pub fn send_message(&self, msg: RawMessage) -> Result<(), ()> {
        let lock = self.inner.sync_channel.lock();
        if let Ok(mut permit) = lock {
            if let Some(snd) = permit.as_mut() {
                if snd.try_send(StreamNotification::Message(msg)).is_err() {
                    // Cloning the `mpsc::Sender` guarantees the allocation of an extra spot in the
                    // buffer, and therefore `try_send` will succeed.
                    debug_assert!(snd
                        .clone()
                        .try_send(StreamNotification::ForceClose)
                        .map(|()| true)
                        .unwrap_or_else(|err| err.is_disconnected()));

                    // Destroy the sender in order to not send more `ForceClose` messages.
                    *permit = None;
                    return Err(());
                }
            } else {
                return Err(());
            }
        }
        return Ok(());
    }

    /// Wait until the remote is ready to accept a message.
    ///
    /// Returns an error in the case where the connection is closed.
    pub async fn reserve_slot(&self) -> Result<Ready<'_>, ()> {
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
    lock: MutexGuard<'a, mpsc::Sender<StreamNotification>>,
}

impl<'a> Ready<'a> {
    /// Consumes this slots reservation and actually queues the notification.
    ///
    /// Returns an error if the substream has been closed.
    pub fn send(mut self, msg: RawMessage) -> Result<(), ()> {
        self.lock
            .start_send(StreamNotification::Message(msg))
            .map_err(|_| ())
    }
}
