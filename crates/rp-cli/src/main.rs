//! Unprivileged requester CLI entry point.

use std::ffi::OsString;

use rp_cli::{
    broker_unavailable_json, invalid_arguments_json, parse_error_json, parse_package_install,
};

fn main() {
    let arguments = match utf8_arguments(std::env::args_os().skip(1).collect()) {
        Some(arguments) => arguments,
        None => {
            println!("{}", invalid_arguments_json());
            return;
        }
    };

    match parse_package_install(&arguments) {
        Ok(_) => println!("{}", broker_unavailable_json()),
        Err(error) => println!("{}", parse_error_json(error)),
    }
}

fn utf8_arguments(arguments: Vec<OsString>) -> Option<Vec<String>> {
    arguments.into_iter().map(|argument| argument.into_string().ok()).collect()
}
