use move_cli::sandbox::utils::on_disk_state_view::*;
use move_vm_runtime::move_vm::*;
use crate::executor::native_functions::*;
use crate::models::script::ScriptBytes;
use crate::executor::gas_cost::zero_cost_model;
use move_cli::sandbox::utils::get_gas_status;
use move_binary_format::errors::VMError;

pub fn execute_script(script: ScriptBytes, state: &OnDiskStateView) -> Result<String, String> {
    let native = NativeFunctions::new();
    let state = OnDiskStateView::default();
    let vm = MoveVM::new(native.move_vm_native_functions).unwrap();
    let mut session = vm.new_session(&state);
    let cost_model = zero_cost_model();
    let mut gas_status = get_gas_status(&cost_model, None).unwrap(); // unmetered
    let script_type_parameters = vec![];
    let vm_args: Vec<Vec<u8>> = vec![];
    let res = session.execute_script(
        script.bytes.to_vec(),
        script_type_parameters.clone(),
        vm_args,
        &mut gas_status);
    if let Err(err) = res {
        //let (changeset, events) = session.finish().map_err(|e| e.into_vm_status())?;
        println!("Error {}", err.into_vm_status());
        Err(String::from("Error"))
    } else {
        Ok(String::from("Success"))
    }
}