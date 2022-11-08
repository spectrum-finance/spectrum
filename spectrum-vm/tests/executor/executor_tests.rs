use std::collections::BTreeMap;
use spectrum_vm::executor::scripts_executor::execute_script;
use std::fs;
use std::fmt::format;
use spectrum_vm::models::script::ScriptBytes;
use move_binary_format::CompiledModule;
use move_binary_format::file_format::CompiledScript;
use move_compiler::{Compiler, Flags};
use move_cli::sandbox::utils::on_disk_state_view::*;
use move_compiler::compiled_unit::{AnnotatedCompiledScript, AnnotatedCompiledUnit, CompiledUnit, NamedCompiledScript};
use move_compiler::shared::NumericalAddress;

#[test]
pub fn test_contract_execution() {

    let path = "/Users/aleksandr/IdeaProjects/move/language/documentation/tutorial/step_1/BasicCoin/sources/FirstContract.move";
    let state = OnDiskStateView::default();
    let compiled_script: Result<Option<CompiledScript>, String> = compile_script(&state, path, false);
    if let Ok(Some(compiled_script)) = compiled_script {
        // let test = CompiledModule::deserialize(&bytes).is_ok();
        let mut script_bytes: Vec<u8> = vec![];
        compiled_script.serialize(&mut script_bytes);
        let script = ScriptBytes { bytes: script_bytes };
        let result = execute_script(script, &state);
        println!("q={}", result.is_ok());
        assert_eq!(result.is_ok(), true)
    } else {
        if let Ok(None) = compiled_script {
            println!("empty script")
        }
        println!("compiled_script={}", compiled_script.is_ok());
        assert_eq!(true, false)
    }
}

fn compile_script(
    state: &OnDiskStateView,
    script_file: &str,
    verbose: bool,
) -> Result<Option<CompiledScript>, String> {
    let mut script_opt: Option<CompiledScript> = None;
    if verbose {
        println!("Compiling transaction script...")
    }
    let map: BTreeMap<String, NumericalAddress> = BTreeMap::new();
    if let (Ok((_files, compiled_units))) = Compiler::from_files(vec![script_file.to_string()], vec![], map)
        .set_flags(Flags::empty().set_sources_shadow_deps(false))
        .build_and_report() {
        for c in compiled_units {
            match c {
                AnnotatedCompiledUnit::Script(scr) => {
                    match scr {
                        AnnotatedCompiledScript{named_script, ..} => {
                            script_opt = Some(named_script.script)
                        }
                    }
                }
                AnnotatedCompiledUnit::Module(_) => {
                    // if verbose {
                    //     println!(
                    //         "Warning: Found module '{}' in file specified for the script. This \
                    //              module will not be published.",
                    //         ident.into_module_ident()
                    //     )
                    // }
                }
            }
        }
    }

        // Compiler::new(&[script_file.to_string()], &[state.interface_files_dir()?])
        //     .set_flags(Flags::empty().set_sources_shadow_deps(false))
        //     .build_and_report()?;

    Ok(script_opt)
}