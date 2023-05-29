use std::collections::{HashMap, HashSet};
use std::time::Instant;

use spectrum_ledger::ModifierId;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ModifierStatus {
    Wanted,
    Requested,
    Received,
    Unknown,
}

pub struct DeliveryStore {
    wanted: HashSet<ModifierId>,
    requested: HashMap<ModifierId, Instant>,
    received: HashSet<ModifierId>,
}

impl DeliveryStore {
    pub fn new() -> Self {
        Self {
            wanted: HashSet::new(),
            requested: HashMap::new(),
            received: HashSet::new(),
        }
    }
}

impl DeliveryStore {
    pub fn wanted(&mut self, mid: ModifierId) {
        self.wanted.insert(mid);
    }

    pub fn requested(&mut self, mid: ModifierId) {
        self.wanted.remove(&mid);
        self.requested.insert(mid, Instant::now());
    }

    pub fn received(&mut self, mid: ModifierId) {
        self.requested.remove(&mid);
        self.requested.remove(&mid);
        self.received.insert(mid);
    }

    pub fn status(&self, mid: &ModifierId) -> ModifierStatus {
        if self.wanted.contains(mid) {
            ModifierStatus::Wanted
        } else if self.received.contains(mid) {
            ModifierStatus::Received
        } else if self.requested.contains_key(mid) {
            ModifierStatus::Requested
        } else {
            ModifierStatus::Unknown
        }
    }
}
