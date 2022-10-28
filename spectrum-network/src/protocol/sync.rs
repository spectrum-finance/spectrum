use crate::protocol_handler::ProtocolHandlerIn;
use futures::channel::mpsc::UnboundedReceiver;

pub mod data;

pub struct SyncProtoc {
    events_recv: UnboundedReceiver<ProtocolHandlerIn>,
}
