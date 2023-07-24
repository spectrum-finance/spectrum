use k256::PublicKey;

struct Idle {}

struct Member {}

struct Leader {}

enum State {
    Idle(Idle),
    Member(Member),
    Leader(Leader),
}

/// Consensus driver for one of committees.
pub struct Consensus<BR, L> {
    identity: PublicKey,
    bridge: BR,
    state: State,
    ledger: L,
}
