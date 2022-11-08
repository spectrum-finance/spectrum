use move_vm_test_utils::gas_schedule::{zero_cost_schedule, CostTable};

// reimport for test
pub fn zero_cost_model() -> CostTable {
    zero_cost_schedule()
}