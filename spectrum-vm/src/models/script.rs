extern crate derive_more;

use derive_more::{From, Into};

#[derive(From, Into)]
pub struct ScriptBytes {
    pub bytes: Vec<u8>
}