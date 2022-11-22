use crate::peer_conn_handler::ConnHandlerError;
use crate::protocol_handler::MalformedMessage;
use crate::types::{ProtocolId, Reputation};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::{Multiaddr, PeerId};

use serde::de::{EnumAccess, Error, SeqAccess, Unexpected, VariantAccess, Visitor};
use serde::ser::SerializeTupleVariant;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::fmt::Formatter;
use std::str::from_utf8;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDestination {
    PeerId(PeerId),
    PeerIdWithAddr(PeerId, Multiaddr),
}

impl PeerDestination {
    pub fn peer_id(&self) -> PeerId {
        match self {
            PeerDestination::PeerId(pid) => *pid,
            PeerDestination::PeerIdWithAddr(pid, _) => *pid,
        }
    }

    pub fn into_addr(self) -> Option<Multiaddr> {
        match self {
            PeerDestination::PeerIdWithAddr(_, addr) => Some(addr),
            PeerDestination::PeerId(_) => None,
        }
    }
}

impl Serialize for PeerDestination {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PeerDestination::PeerId(pid) => {
                let mut tv = serializer.serialize_tuple_variant("PeerDestination", 0, "PeerId", 1)?;
                tv.serialize_field(&*pid.to_bytes())?;
                tv.end()
            }
            PeerDestination::PeerIdWithAddr(pid, maddr) => {
                let mut tv = serializer.serialize_tuple_variant("PeerDestination", 1, "PeerIdWithAddr", 2)?;
                tv.serialize_field(&*pid.to_bytes())?;
                tv.serialize_field(maddr)?;
                tv.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for PeerDestination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PeerIdVisitor;
        impl<'de> Visitor<'de> for PeerIdVisitor {
            type Value = PeerId;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("Expected PeerId")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                PeerId::from_bytes(v).map_err(|_| Error::custom("Cannon deserialize PeerId"))
            }
        }

        struct PeerIdWithAddrVisitor;
        impl<'de> Visitor<'de> for PeerIdWithAddrVisitor {
            type Value = (PeerId, Multiaddr);

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("Expected (PeerId, Multiaddr)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let pid = seq.next_element::<&[u8]>()?;
                let maddr = seq.next_element()?;
                match (pid, maddr) {
                    (Some(pid), Some(maddr)) => PeerId::from_bytes(pid)
                        .map_err(|_| Error::custom("Cannon deserialize PeerId"))
                        .map(|pid| (pid, maddr)),
                    (Some(_), None) => Err(Error::missing_field("Multiaddr")),
                    (None, _) => Err(Error::missing_field("PeerId")),
                }
            }
        }

        enum Field {
            PeerId,
            PeerIdWithAddr,
        }
        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;
                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                        formatter.write_str("Expected PeerId or PeerIdWithAddr")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            "PeerId" => Ok(Field::PeerId),
                            "PeerIdWithAddr" => Ok(Field::PeerIdWithAddr),
                            _ => Err(Error::unknown_variant(v, VARIANTS)),
                        }
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            b"PeerId" => Ok(Field::PeerId),
                            b"PeerIdWithAddr" => Ok(Field::PeerIdWithAddr),
                            _ => match from_utf8(v) {
                                Ok(value) => Err(Error::unknown_variant(value, VARIANTS)),
                                Err(_) => Err(Error::invalid_value(Unexpected::Bytes(v), &self)),
                            },
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PeerDestinationVisitor;
        impl<'de> Visitor<'de> for PeerDestinationVisitor {
            type Value = PeerDestination;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("Expected PeerDestination")
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match data.variant()? {
                    (Field::PeerId, v) => v.tuple_variant(1, PeerIdVisitor).map(PeerDestination::PeerId),
                    (Field::PeerIdWithAddr, v) => v
                        .tuple_variant(2, PeerIdWithAddrVisitor)
                        .map(|(pid, maddr)| PeerDestination::PeerIdWithAddr(pid, maddr)),
                }
            }
        }

        const VARIANTS: &'static [&'static str] = &["PeerId", "PeerIdWithAddr"];
        deserializer.deserialize_enum("PeerDestination", VARIANTS, PeerDestinationVisitor)
    }
}

impl From<PeerDestination> for DialOpts {
    fn from(p: PeerDestination) -> Self {
        match p {
            PeerDestination::PeerId(pid) => DialOpts::peer_id(pid)
                .condition(PeerCondition::NotDialing)
                .build(),
            PeerDestination::PeerIdWithAddr(pid, addr) => DialOpts::peer_id(pid)
                .condition(PeerCondition::NotDialing)
                .addresses(vec![addr])
                .build(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationChange {
    MalformedMessage(MalformedMessage),
    NoResponse,
    TooSlow,
}

impl ReputationChange {
    /// Returns true if reputation is downgraded.
    pub fn is_downgrade(&self) -> bool {
        match self {
            ReputationChange::MalformedMessage(_) => true,
            ReputationChange::NoResponse => true,
            ReputationChange::TooSlow => true,
        }
    }
}

impl From<ReputationChange> for i32 {
    fn from(c: ReputationChange) -> Self {
        match c {
            ReputationChange::MalformedMessage(_) => -10,
            ReputationChange::NoResponse => -10,
            ReputationChange::TooSlow => -10,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionLossReason {
    /// Connection has been explicitly reset by peer.
    ResetByPeer,
    /// Connection has been closed by us because of the err.
    Reset(ConnHandlerError),
    /// Connection has been closed for an unknown reason.
    Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connected(ConnectionDirection),
    NotConnected,
}

impl ConnectionState {
    pub fn is_connected(self) -> bool {
        match self {
            ConnectionState::Connected(_) => true,
            ConnectionState::NotConnected => false,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound(bool), // confirmed or not
}

#[derive(PartialEq, Eq, Debug)]
pub struct Peer {
    pub addr: Multiaddr,
    pub info: PeerInfo,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PeerInfo {
    /// Is this peer a reserved one.
    /// We should do our best to remain connected to reserved peers.
    pub is_reserved: bool,
    /// Is this peer a bootstrapping one.
    pub is_boot: bool,
    /// An address this peer can be reached at.
    pub addr: Option<Multiaddr>,
    /// Reputation value of the node, between `i32::MIN` (we hate that node) and
    /// `i32::MAX` (we love that node).
    pub reputation: Reputation,
    pub state: ConnectionState,
    /// How many successful connections with this node do we have.
    pub num_connections: u32,
    /// Time last successful connection attempt was made.
    pub last_handshake: Option<Instant>,
    /// Backoff of the next outbound connection attempt.
    pub outbound_backoff_until: Option<Instant>,
    /// Protocols supported by the peer. `None` if unknown.
    pub supported_protocols: Option<Vec<ProtocolId>>,
}

impl PeerInfo {
    pub fn new(addr: Option<Multiaddr>, is_reserved: bool, is_boot: bool) -> Self {
        Self {
            is_reserved,
            is_boot,
            addr,
            reputation: Reputation::initial(),
            state: ConnectionState::NotConnected,
            num_connections: 0,
            last_handshake: None,
            outbound_backoff_until: None,
            supported_protocols: None,
        }
    }

    pub fn supports(&self, protocol: &ProtocolId) -> Option<bool> {
        self.supported_protocols.as_ref().map(|ps| ps.contains(protocol))
    }

    pub fn confirm_new_conn(&mut self) {
        let _ = self.num_connections.saturating_add(1);
    }
}

/// Policy of protocols allocation defines the way we should
/// actively allocate connections for a particular protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolAllocationPolicy {
    /// Allocate up to the specified % of all connectons.
    Bounded(usize),
    /// Allocate as many as possible connections.
    Max,
    /// Do not allocate any connections.
    Zero,
}
