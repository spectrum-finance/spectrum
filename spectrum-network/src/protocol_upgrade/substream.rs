use crate::protocol_upgrade::message::Approve;
use crate::types::RawMessage;
use asynchronous_codec::Framed;
use futures::{AsyncRead, AsyncWrite, Sink, Stream};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};
use unsigned_varint::codec::UviBytes;
use void::Void;

/// State of the protocol approve sending process.
#[derive(Debug, Clone)]
pub enum ProtocolApproveState {
    /// Waiting for the node to give us the approve message.
    NotSent,
    /// Node gave us the Approve message. Trying to push it in the socket.
    PendingSend(RawMessage),
    /// Approve message was pushed in the socket. Still need to flush.
    Flush,
    /// Approve message successfully sent and flushed.
    Sent,
    /// Remote has closed their writing side. We close our own writing side in return.
    ClosingInResponseToRemote,
    /// Both our side and the remote have closed their writing side.
    BothSidesClosed,
}

/// Error generated by sending on a notifications out substream.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolSubstreamOutError {
    /// I/O error on the substream.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A substream for incoming messages.
///
/// When creating, this struct starts in a state in which we must first send back a handshake
/// message to the peer. No message will come before this has been done.
#[pin_project::pin_project]
pub struct ProtocolSubstreamIn<Substream> {
    #[pin]
    pub socket: Framed<Substream, UviBytes<io::Cursor<Vec<u8>>>>,
    /// None in the case protocol approve is not required.
    pub approve_state: Option<ProtocolApproveState>,
}

impl<Substream> ProtocolSubstreamIn<Substream>
where
    Substream: AsyncRead + AsyncWrite + Unpin,
{
    pub fn send_approve(&mut self) {
        if matches!(self.approve_state, Some(ProtocolApproveState::NotSent)) {
            self.approve_state = Some(ProtocolApproveState::PendingSend(Approve().into()));
        }
    }

    /// Equivalent to `Stream::poll_next`, except that it only drives the handshake and is
    /// guaranteed to not generate any notification.
    pub fn poll_process_handshake(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Void, io::Error>> {
        let mut this = self.project();
        loop {
            if let Some(state) = this.approve_state {
                match mem::replace(state, ProtocolApproveState::Sent) {
                    ProtocolApproveState::PendingSend(msg) => {
                        match Sink::poll_ready(this.socket.as_mut(), cx) {
                            Poll::Ready(_) => {
                                *this.approve_state = Some(ProtocolApproveState::Flush);
                                match Sink::start_send(this.socket.as_mut(), io::Cursor::new(msg.into())) {
                                    Ok(()) => {}
                                    Err(err) => return Poll::Ready(Err(err)),
                                }
                            }
                            Poll::Pending => {
                                *this.approve_state = Some(ProtocolApproveState::PendingSend(msg));
                                return Poll::Pending;
                            }
                        }
                    }
                    ProtocolApproveState::Flush => match Sink::poll_flush(this.socket.as_mut(), cx)? {
                        Poll::Ready(()) => *this.approve_state = Some(ProtocolApproveState::Sent),
                        Poll::Pending => {
                            *this.approve_state = Some(ProtocolApproveState::Flush);
                            return Poll::Pending;
                        }
                    },
                    st @ ProtocolApproveState::NotSent
                    | st @ ProtocolApproveState::Sent
                    | st @ ProtocolApproveState::ClosingInResponseToRemote
                    | st @ ProtocolApproveState::BothSidesClosed => {
                        *this.approve_state = Some(st);
                        return Poll::Pending;
                    }
                }
            } else {
                return Poll::Pending;
            }
        }
    }
}

impl<Substream> Stream for ProtocolSubstreamIn<Substream>
where
    Substream: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<RawMessage, io::Error>;

    /// First tries to drive handshake delivery to completion if neccessary.
    /// Then process incoming bytes.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            match this.approve_state.take() {
                Some(ProtocolApproveState::Sent) | None => {
                    match Stream::poll_next(this.socket.as_mut(), cx) {
                        Poll::Ready(None) => {
                            *this.approve_state = Some(ProtocolApproveState::ClosingInResponseToRemote)
                        }
                        Poll::Ready(Some(msg)) => {
                            *this.approve_state = Some(ProtocolApproveState::Sent);
                            return Poll::Ready(Some(msg.map(RawMessage::from)));
                        }
                        Poll::Pending => {
                            *this.approve_state = Some(ProtocolApproveState::Sent);
                            return Poll::Pending;
                        }
                    }
                }
                Some(ProtocolApproveState::NotSent) => {
                    *this.approve_state = Some(ProtocolApproveState::NotSent);
                    return Poll::Pending;
                }
                Some(ProtocolApproveState::PendingSend(msg)) => {
                    match Sink::poll_ready(this.socket.as_mut(), cx) {
                        Poll::Ready(_) => {
                            *this.approve_state = Some(ProtocolApproveState::Flush);
                            match Sink::start_send(this.socket.as_mut(), io::Cursor::new(msg.into())) {
                                Ok(()) => {}
                                Err(err) => return Poll::Ready(Some(Err(err))),
                            }
                        }
                        Poll::Pending => {
                            *this.approve_state = Some(ProtocolApproveState::PendingSend(msg));
                            return Poll::Pending;
                        }
                    }
                }
                Some(ProtocolApproveState::Flush) => match Sink::poll_flush(this.socket.as_mut(), cx)? {
                    Poll::Ready(()) => *this.approve_state = Some(ProtocolApproveState::Sent),
                    Poll::Pending => {
                        *this.approve_state = Some(ProtocolApproveState::Flush);
                        return Poll::Pending;
                    }
                },
                Some(ProtocolApproveState::ClosingInResponseToRemote) => {
                    match Sink::poll_close(this.socket.as_mut(), cx)? {
                        Poll::Ready(()) => *this.approve_state = Some(ProtocolApproveState::BothSidesClosed),
                        Poll::Pending => {
                            *this.approve_state = Some(ProtocolApproveState::ClosingInResponseToRemote);
                            return Poll::Pending;
                        }
                    }
                }
                Some(ProtocolApproveState::BothSidesClosed) => return Poll::Ready(None),
            }
        }
    }
}

/// A substream for outgoing notification messages.
#[pin_project::pin_project]
pub struct ProtocolSubstreamOut<Substream> {
    /// Substream where to send messages.
    #[pin]
    pub socket: Framed<Substream, UviBytes<io::Cursor<Vec<u8>>>>,
}

impl<Substream> Sink<RawMessage> for ProtocolSubstreamOut<Substream>
where
    Substream: AsyncRead + AsyncWrite + Unpin,
{
    type Error = ProtocolSubstreamOutError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        Sink::poll_ready(this.socket.as_mut(), cx).map_err(ProtocolSubstreamOutError::Io)
    }

    fn start_send(self: Pin<&mut Self>, item: RawMessage) -> Result<(), Self::Error> {
        let mut this = self.project();
        Sink::start_send(this.socket.as_mut(), io::Cursor::new(item.into()))
            .map_err(ProtocolSubstreamOutError::Io)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        Sink::poll_flush(this.socket.as_mut(), cx).map_err(ProtocolSubstreamOutError::Io)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        Sink::poll_close(this.socket.as_mut(), cx).map_err(ProtocolSubstreamOutError::Io)
    }
}
