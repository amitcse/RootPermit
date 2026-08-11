use rp_protocol::{decode, ApprovalContext, Domain, Request};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize)]
struct PositiveManifest {
    version: u64,
    vectors: Vec<PositiveVector>,
}

#[derive(Debug, Deserialize)]
struct PositiveVector {
    name: String,
    schema: String,
    cbor_hex: String,
    digest_domain: String,
    digest_hex: String,
    webauthn_challenge_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NegativeManifest {
    version: u64,
    vectors: Vec<NegativeVector>,
}

#[derive(Debug, Deserialize)]
struct NegativeVector {
    name: String,
    target: String,
    cbor_hex: String,
    error: String,
}

fn vectors_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol-vectors").join(name)
}

#[test]
fn positive_vectors_are_stable_and_match_digests() {
    let manifest: PositiveManifest = serde_json::from_slice(&fs::read(vectors_path("v1/manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.version, 1);
    for vector in manifest.vectors {
        let bytes = hex::decode(&vector.cbor_hex).unwrap();
        match vector.schema.as_str() {
            "Request" => {
                let value = Request::decode(&bytes).unwrap_or_else(|error| panic!("{}: {error}", vector.name));
                assert_eq!(value.canonical_bytes().unwrap(), bytes, "{}", vector.name);
                assert_eq!(hex::encode(value.digest().unwrap()), vector.digest_hex, "{}", vector.name);
                assert_eq!(vector.digest_domain, "request");
            }
            "ApprovalContext" => {
                let value = ApprovalContext::decode(&bytes).unwrap_or_else(|error| panic!("{}: {error}", vector.name));
                assert_eq!(value.canonical_bytes().unwrap(), bytes, "{}", vector.name);
                assert_eq!(hex::encode(value.digest().unwrap()), vector.digest_hex, "{}", vector.name);
                assert_eq!(vector.digest_domain, "decision");
                assert_eq!(hex::encode(value.webauthn_challenge().unwrap()), vector.webauthn_challenge_hex.unwrap(), "{}", vector.name);
            }
            schema => panic!("{}: unsupported vector schema {schema}", vector.name),
        }
    }
}

#[test]
fn negative_vectors_fail_closed() {
    let manifest: NegativeManifest = serde_json::from_slice(&fs::read(vectors_path("negative/manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.version, 1);
    for vector in manifest.vectors {
        let bytes = hex::decode(&vector.cbor_hex).unwrap();
        let result = match vector.target.as_str() {
            "cbor" => decode(&bytes).map(|_| ()),
            "Request" => Request::decode(&bytes).map(|_| ()),
            target => panic!("{}: unsupported negative vector target {target}", vector.name),
        };
        assert!(result.is_err(), "{} ({}) unexpectedly decoded", vector.name, vector.error);
    }
}

#[test]
fn domain_labels_are_not_interchangeable() {
    assert_ne!(Domain::Request.label(), Domain::Decision.label());
    assert_ne!(Domain::Decision.label(), Domain::WebAuthnChallenge.label());
}
