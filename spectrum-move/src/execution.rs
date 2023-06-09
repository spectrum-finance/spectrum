use std::collections::HashMap;

use void::Void;

use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, StructTag};
use move_core_types::resolver::{ModuleResolver, ResourceResolver};

use crate::{SerializedModule, SerializedValue};

pub struct ExecutionScope {
    pub modules: HashMap<Identifier, SerializedModule>,
    pub resources: HashMap<StructTag, SerializedValue>,
}

impl ModuleResolver for ExecutionScope {
    type Error = Void;

    fn get_module(&self, id: &ModuleId) -> Result<Option<Vec<u8>>, Void> {
        Ok(self.modules.get(id.name()).cloned().map(<Vec<u8>>::from))
    }
}

impl ResourceResolver for ExecutionScope {
    type Error = Void;

    fn get_resource(&self, _: &AccountAddress, typ: &StructTag) -> Result<Option<Vec<u8>>, Void> {
        Ok(self.resources.get(typ).cloned().map(<Vec<u8>>::from))
    }
}
