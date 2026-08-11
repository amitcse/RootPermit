//! Strict, non-privileged command parsing for RootPermit clients.
//!
//! This crate intentionally does not talk to a broker yet.  The requester
//! surface accepts only one typed operation; successful parsing therefore
//! reports broker unavailability rather than pretending that a request ran.

use std::fmt;

/// The only requester operation admitted by the initial CLI.
#[derive(Debug, Eq, PartialEq)]
pub struct PackageInstallRequest {
    /// A Debian binary package base name, never a version or architecture.
    pub package_name: String,
    /// Caller-selected idempotency key. The future broker binds it to the UID.
    pub operation_key: String,
    /// Bounded untrusted display text, excluded from authority fields.
    pub note: Option<String>,
}

/// Root administration names reserved for the future root-controlled client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCommand {
    StartPairing,
    ChangeCredentials,
    Reconcile,
    Export,
    Purge,
    Unenroll,
}

/// Safe, bounded parser failures that may be returned to a requester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidCommand,
    InvalidPackageName,
    InvalidOperationKey,
    InvalidNote,
    MissingValue,
    UnexpectedArgument,
    UnsupportedAdminCommand,
}

impl ParseError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCommand | Self::UnsupportedAdminCommand => "invalid_command",
            Self::InvalidPackageName => "invalid_package_name",
            Self::InvalidOperationKey => "invalid_operation_key",
            Self::InvalidNote => "invalid_note",
            Self::MissingValue | Self::UnexpectedArgument => "invalid_arguments",
        }
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidCommand => "only package install is supported",
            Self::InvalidPackageName => "package name must be a Debian binary package base name",
            Self::InvalidOperationKey => "operation key has an invalid format",
            Self::InvalidNote => "note exceeds the safe text contract",
            Self::MissingValue => "a required argument value is missing",
            Self::UnexpectedArgument => "unknown flag or unexpected argument",
            Self::UnsupportedAdminCommand => "unknown root administration command",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ParseError {}

/// Parses exactly `package install <name> --operation-key <key> [--note <text>]`.
///
/// No alternate argument ordering or aliases are accepted. In particular,
/// versions, paths, URLs, architectures, APT options, and unknown flags fail
/// before any future broker connection can be attempted.
pub fn parse_package_install(arguments: &[String]) -> Result<PackageInstallRequest, ParseError> {
    if arguments.first().map(String::as_str) != Some("package")
        || arguments.get(1).map(String::as_str) != Some("install")
    {
        return Err(ParseError::InvalidCommand);
    }

    let package_name = arguments.get(2).ok_or(ParseError::MissingValue)?;
    if !is_binary_package_name(package_name) {
        return Err(ParseError::InvalidPackageName);
    }

    if arguments.get(3).map(String::as_str) != Some("--operation-key") {
        return Err(if arguments.get(3).is_some() {
            ParseError::UnexpectedArgument
        } else {
            ParseError::MissingValue
        });
    }

    let operation_key = arguments.get(4).ok_or(ParseError::MissingValue)?;
    if !is_operation_key(operation_key) {
        return Err(ParseError::InvalidOperationKey);
    }

    let note = match arguments.get(5).map(String::as_str) {
        None => None,
        Some("--note") => {
            let value = arguments.get(6).ok_or(ParseError::MissingValue)?;
            if !is_safe_note(value) {
                return Err(ParseError::InvalidNote);
            }
            Some(value.clone())
        }
        Some(_) => return Err(ParseError::UnexpectedArgument),
    };

    let expected_length = if note.is_some() { 7 } else { 5 };
    if arguments.len() != expected_length {
        return Err(ParseError::UnexpectedArgument);
    }

    Ok(PackageInstallRequest {
        package_name: package_name.clone(),
        operation_key: operation_key.clone(),
        note,
    })
}

/// Parses a reserved root-admin action name. It has no privileged behavior.
pub fn parse_admin_command(arguments: &[String]) -> Result<AdminCommand, ParseError> {
    if arguments.len() != 1 {
        return Err(ParseError::UnexpectedArgument);
    }
    match arguments[0].as_str() {
        "start-pairing" => Ok(AdminCommand::StartPairing),
        "change-credentials" => Ok(AdminCommand::ChangeCredentials),
        "reconcile" => Ok(AdminCommand::Reconcile),
        "export" => Ok(AdminCommand::Export),
        "purge" => Ok(AdminCommand::Purge),
        "unenroll" => Ok(AdminCommand::Unenroll),
        _ => Err(ParseError::UnsupportedAdminCommand),
    }
}

/// Renders a parser failure under the stable, one-line JSON contract.
#[must_use]
pub fn parse_error_json(error: ParseError) -> String {
    error_json(error.code(), error.message())
}

/// Renders the invalid-argument JSON response without reflecting an OS string.
#[must_use]
pub fn invalid_arguments_json() -> String {
    error_json("invalid_arguments", "arguments must be valid UTF-8")
}

/// M2 has no Unix-socket transport implementation yet; this is intentionally
/// distinct from a denied operation so callers can retry after installation.
#[must_use]
pub fn broker_unavailable_json() -> String {
    error_json(
        "temporarily_unavailable",
        "local broker RPC is not implemented",
    )
}

/// The admin binary must never claim that local command-line parsing conveys
/// root authority. The future broker performs root peer authorization.
#[must_use]
pub fn admin_unavailable_json() -> String {
    error_json(
        "temporarily_unavailable",
        "root administration RPC is not implemented",
    )
}

fn error_json(code: &str, message: &str) -> String {
    format!(r#"{{"ok":false,"error":{{"code":"{code}","message":"{message}"}}}}"#)
}

fn is_binary_package_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=64).contains(&bytes.len())
        && matches!(bytes.first(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.iter().all(u8::is_ascii)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'+' | b'-' | b'.')
        })
}

fn is_operation_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    (16..=128).contains(&bytes.len())
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_')
        })
}

fn is_safe_note(value: &str) -> bool {
    value.len() <= 512 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::{
        admin_unavailable_json, broker_unavailable_json, invalid_arguments_json, parse_admin_command,
        parse_error_json, parse_package_install, AdminCommand, ParseError,
    };

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn accepts_only_the_typed_package_install_shape() {
        let request = parse_package_install(&arguments(&[
            "package",
            "install",
            "ffmpeg",
            "--operation-key",
            "install-ffmpeg-01",
            "--note",
            "Needed for local transcoding",
        ]))
        .expect("typed request should parse");

        assert_eq!(request.package_name, "ffmpeg");
        assert_eq!(request.operation_key, "install-ffmpeg-01");
        assert_eq!(request.note.as_deref(), Some("Needed for local transcoding"));
    }

    #[test]
    fn rejects_versions_urls_paths_architectures_and_apt_options() {
        for value in [
            "ffmpeg=7.0",
            "https://example.test/package.deb",
            "../ffmpeg",
            "ffmpeg:amd64",
            "--allow-unauthenticated",
        ] {
            let result = parse_package_install(&arguments(&[
                "package",
                "install",
                value,
                "--operation-key",
                "safe-key-12345678",
            ]));
            assert_eq!(result, Err(ParseError::InvalidPackageName), "{value}");
        }
    }

    #[test]
    fn rejects_reordered_or_unknown_flags_and_unbounded_notes() {
        assert_eq!(
            parse_package_install(&arguments(&[
                "package",
                "install",
                "ffmpeg",
                "--note",
                "x",
                "--operation-key",
                "safe-key-12345678",
            ])),
            Err(ParseError::UnexpectedArgument)
        );
        assert_eq!(
            parse_package_install(&arguments(&[
                "package",
                "install",
                "ffmpeg",
                "--operation-key",
                "safe-key-12345678",
                "--apt-option",
                "x",
            ])),
            Err(ParseError::UnexpectedArgument)
        );
        assert_eq!(
            parse_package_install(&arguments(&[
                "package",
                "install",
                "ffmpeg",
                "--operation-key",
                "safe-key-12345678",
                "--note",
                &"x".repeat(513),
            ])),
            Err(ParseError::InvalidNote)
        );
    }

    #[test]
    fn operation_keys_match_the_broker_opaque_key_contract() {
        for key in ["short-key", "contains.dot-123456", "contains/slash-1234"] {
            assert_eq!(
                parse_package_install(&arguments(&[
                    "package", "install", "ffmpeg", "--operation-key", key,
                ])),
                Err(ParseError::InvalidOperationKey),
                "{key}"
            );
        }
    }

    #[test]
    fn parser_errors_and_unavailable_responses_do_not_echo_input() {
        let secret_like_input = "https://attacker.invalid/token";
        let parsed = parse_package_install(&arguments(&[
            "package",
            "install",
            secret_like_input,
            "--operation-key",
                "safe-key-12345678",
        ]));
        assert_eq!(parsed, Err(ParseError::InvalidPackageName));

        let requester_json = broker_unavailable_json();
        let admin_json = admin_unavailable_json();
        assert_eq!(
            requester_json,
            r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"local broker RPC is not implemented"}}"#
        );
        assert_eq!(
            admin_json,
            r#"{"ok":false,"error":{"code":"temporarily_unavailable","message":"root administration RPC is not implemented"}}"#
        );
        assert!(!requester_json.contains(secret_like_input));
        assert_eq!(
            parse_error_json(ParseError::InvalidPackageName),
            r#"{"ok":false,"error":{"code":"invalid_package_name","message":"package name must be a Debian binary package base name"}}"#
        );
        assert_eq!(
            invalid_arguments_json(),
            r#"{"ok":false,"error":{"code":"invalid_arguments","message":"arguments must be valid UTF-8"}}"#
        );
    }

    #[test]
    fn admin_boundary_reserves_only_known_actions() {
        assert_eq!(
            parse_admin_command(&arguments(&["start-pairing"])),
            Ok(AdminCommand::StartPairing)
        );
        assert_eq!(
            parse_admin_command(&arguments(&["start-pairing", "extra"])),
            Err(ParseError::UnexpectedArgument)
        );
        assert_eq!(
            parse_admin_command(&arguments(&["sudo"])),
            Err(ParseError::UnsupportedAdminCommand)
        );
    }
}
