#![allow(non_snake_case, non_camel_case_types,dead_code,unused_imports)]

mod runpe;
mod common;
mod unhook;
mod patch;

use clap::Parser;
use common::*;

#[cfg(feature = "exe")]
fn main() {
    let cli = Cli::parse();

    let result = match cli.mode {
        Mode::Clr { args, base, key, iv, assembly, unencrypted} => {
            execute_clr_mode(args, base, key, iv, assembly, unencrypted)
        },
        Mode::Ps { command, script } => {
            execute_ps_mode(command, script)
        },
        Mode::Bof { args, base, key, iv, bof, unencrypted} => {
            execute_bof_mode(args, base, key, iv, bof, unencrypted)
        },
        Mode::Pe { args, base, key, iv, pe, unencrypted} => {
            execute_pe_mode(args, base, key, iv, pe, unencrypted)
        },
    };

    match result {
        Ok(()) => println!("Operation completed successfully."),
        Err(e) => eprintln!("Error: {}", e),
    }
}