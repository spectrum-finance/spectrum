use asynchronous_codec::Framed;
use std::io;
use unsigned_varint::codec::UviBytes;

/// A substream for incoming notification messages.
///
/// When creating, this struct starts in a state in which we must first send back a handshake
/// message to the remote. No message will come before this has been done.
#[pin_project::pin_project]
pub struct ProtocolSubstreamIn<Substream> {
    #[pin]
    pub socket: Framed<Substream, UviBytes<io::Cursor<Vec<u8>>>>,
    pub handshake: ProtocolSubstreamHandshakeState,
}

/// State of the handshake sending back process.
pub enum ProtocolSubstreamHandshakeState {
    /// Waiting for the user to give us the handshake message.
    NotSent,
    /// Initial handshake not required.
    NotRequired,
    /// User gave us the handshake message. Trying to push it in the socket.
    PendingSend(Vec<u8>),
    /// Handshake message was pushed in the socket. Still need to flush.
    Flush,
    /// Handshake message successfully sent and flushed.
    Sent,
    /// Remote has closed their writing side. We close our own writing side in return.
    ClosingInResponseToRemote,
    /// Both our side and the remote have closed their writing side.
    BothSidesClosed,
}

/// A substream for outgoing notification messages.
#[pin_project::pin_project]
pub struct ProtocolSubstreamOut<TSubstream> {
    /// Substream where to send messages.
    #[pin]
    pub socket: Framed<TSubstream, UviBytes<io::Cursor<Vec<u8>>>>,
}
