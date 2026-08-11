//! Root administration command boundary entry point.
//!
//! This binary is deliberately inert until the broker RPC layer can obtain the
//! kernel peer identity. It neither checks a mutable environment variable nor
//! treats local command execution as proof of root authority.

use std::ffi::OsString;

use rp_cli::{
    admin_unavailable_json, invalid_arguments_json, parse_admin_command, parse_error_json,
};

fn main() {
    let arguments = match utf8_arguments(std::env::args_os().skip(1).collect()) {
        Some(arguments) => arguments,
        None => {
            println!("{}", invalid_arguments_json());
            return;
        }
    };

    match parse_admin_command(&arguments) {
        Ok(_) => println!("{}", admin_unavailable_json()),
        Err(error) => println!("{}", parse_error_json(error)),
    }
}

fn utf8_arguments(arguments: Vec<OsString>) -> Option<Vec<String>> {
    arguments.into_iter().map(OsString::into_string).collect()
}
