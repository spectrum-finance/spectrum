use k256::PublicKey;

struct Idle {}

struct Member {}

struct Leader {}

enum Role {
    Idle(Idle),
    Member(Member),
    Leader(Leader),
}

/// Consensus driver for one of committees.
pub struct Consensus<BR> {
    identity: PublicKey,
    bridge: BR,
    role: Role,
}
