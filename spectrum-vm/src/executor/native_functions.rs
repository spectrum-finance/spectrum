use move_vm_runtime::native_functions::NativeFunctionTable;
use move_stdlib::natives::*;
use move_core_types::language_storage::CORE_CODE_ADDRESS;

pub struct NativeFunctions {
    pub(crate) move_vm_native_functions: NativeFunctionTable,
}

impl NativeFunctions {
    pub fn new() -> Self {
        let natives = all_natives(
            CORE_CODE_ADDRESS,
            // We may want to switch to a different gas schedule in the future, but for now,
            // the all-zero one should be enough.
            move_stdlib::natives::GasParameters::zeros(),
        )
        .into_iter()
        .chain(
            nursery_natives(
                CORE_CODE_ADDRESS,
                // We may want to switch to a different gas schedule in the future, but for now,
                // the all-zero one should be enough.
                move_stdlib::natives::NurseryGasParameters::zeros(),
        ))
        .collect::<Vec<_>>(); // we can add our native functions here, like in diem framework

        Self {
            move_vm_native_functions: natives,
        }
    }
}