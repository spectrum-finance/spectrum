use ergo_lib::ergotree_ir::chain::{address::Address, ergo_box::box_value::BoxValue};

pub struct Deposit {
    pub value: BoxValue,
    pub depositor_address: Address,
}
