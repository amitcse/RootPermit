use ed25519_dalek::VerifyingKey;
use rp_protocol::{decode, ApprovalContext, CoseSign1, DecisionSubmission, Domain, KeyRole, Request, VerificationKey, VerificationPolicy};
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

#[derive(Debug, Deserialize)]
struct CoseManifest {
    version: u64,
    vectors: Vec<CoseVector>,
}

#[derive(Debug, Deserialize)]
struct CoseVector {
    name: String,
    cose_hex: String,
    payload_hex: String,
    public_key_hex: String,
    kid_hex: String,
    content_type: u64,
    domain: String,
    role: String,
    now_utc: i64,
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
            "DecisionSubmission" => {
                let value = DecisionSubmission::decode(&bytes).unwrap_or_else(|error| panic!("{}: {error}", vector.name));
                assert_eq!(value.canonical_bytes().unwrap(), bytes, "{}", vector.name);
                assert_eq!(vector.digest_domain, "none");
            }
            schema => panic!("{}: unsupported vector schema {schema}", vector.name),
        }
    }
}

#[test]
fn cose_known_answer_vectors_verify_with_exact_external_aad() {
    let manifest: CoseManifest = serde_json::from_slice(&fs::read(vectors_path("cose-v1/manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.version, 1);
    for vector in manifest.vectors {
        let envelope = CoseSign1::decode(&hex::decode(&vector.cose_hex).unwrap()).unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        assert_eq!(hex::encode(&envelope.payload), vector.payload_hex, "{}", vector.name);
        let public_key: [u8; 32] = hex::decode(&vector.public_key_hex).unwrap().try_into().unwrap();
        let key = VerificationKey::new(
            hex::decode(&vector.kid_hex).unwrap(),
            VerifyingKey::from_bytes(&public_key).unwrap(),
            0,
            100,
            vec![match vector.role.as_str() { "broker" => KeyRole::Broker, role => panic!("{}: unsupported role {role}", vector.name) }],
        ).unwrap();
        let domain = match vector.domain.as_str() { "request" => Domain::Request, domain => panic!("{}: unsupported domain {domain}", vector.name) };
        envelope.verify(&key, VerificationPolicy { content_type: vector.content_type, domain, required_role: KeyRole::Broker, now_utc: vector.now_utc }).unwrap_or_else(|error| panic!("{}: {error}", vector.name));
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
            "DecisionSubmission" => DecisionSubmission::decode(&bytes).map(|_| ()),
            "CoseSign1" => CoseSign1::decode(&bytes).map(|_| ()),
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
