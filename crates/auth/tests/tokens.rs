use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use sg_auth::*;
use sg_core::{crypto, KeyInput, Vault};
use std::{sync::Arc, time::Duration};
use tempfile::tempdir;

fn svc() -> (tempfile::TempDir, Arc<Vault>, TokenService) {
    let dir = tempdir().unwrap();
    let v = Arc::new(
        Vault::init(
            &dir.path().join("v.db"),
            KeyInput::Raw(crypto::random_key()),
        )
        .unwrap(),
    );
    let s = TokenService::new(v.clone()).unwrap();
    (dir, v, s)
}

/// Loads the persisted signing key (test-only) so tests can forge correctly signed tokens.
fn signing_key(v: &Vault) -> SigningKey {
    let blob: Vec<u8> = v
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'token_signing_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let raw = v.open_value(b"sg:token-signing-key", &blob).unwrap();
    SigningKey::from_bytes(raw.as_slice().try_into().unwrap())
}

/// Builds a token signed with the vault's real key from arbitrary header/payload bytes.
fn forge(v: &Vault, header: &str, payload: &str) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    let sig = signing_key(v).sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

const GOOD_HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

fn register(v: &Vault, jti: &str) {
    v.conn()
        .execute(
            "INSERT INTO tokens (jti, machine, role, created_at, token_hash) VALUES (?1, 'm', 'r', 1, 'x')",
            [jti],
        )
        .unwrap();
}

#[test]
fn issue_and_verify_roundtrip() {
    let (_d, _v, s) = svc();
    let t = s.issue("laptop", "developer", None).unwrap();
    let id = s.verify(&t.token).unwrap();
    assert_eq!(
        (id.machine.as_str(), id.role.as_str(), id.jti.as_str()),
        ("laptop", "developer", t.jti.as_str())
    );
}

#[test]
fn signing_key_persists_across_service_instances() {
    let (_d, v, s) = svc();
    let t = s.issue("laptop", "developer", None).unwrap();
    let s2 = TokenService::new(v).unwrap();
    assert!(s2.verify(&t.token).is_ok());
}

#[test]
fn expired_token_is_rejected() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", Some(Duration::from_secs(0))).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert!(matches!(s.verify(&t.token), Err(AuthError::Expired(_))));
}

#[test]
fn revoked_token_is_rejected_and_machine_revocation_counts() {
    let (_d, _v, s) = svc();
    let a = s.issue("laptop", "developer", None).unwrap();
    let b = s.issue("laptop", "reviewer", None).unwrap();
    let c = s.issue("other", "reviewer", None).unwrap();
    s.revoke(&a.jti).unwrap();
    assert!(matches!(s.verify(&a.token), Err(AuthError::Revoked(_))));
    assert_eq!(s.revoke_machine("laptop").unwrap(), 1);
    assert!(matches!(s.verify(&b.token), Err(AuthError::Revoked(_))));
    assert!(s.verify(&c.token).is_ok());
}

#[test]
fn tampered_payload_and_foreign_signer_are_rejected() {
    let (_d, _v, s) = svc();
    let (_d2, _v2, other) = svc();
    let t = s.issue("m", "reviewer", None).unwrap();
    assert!(other.verify(&t.token).is_err());
    let parts: Vec<&str> = t.token.split('.').collect();
    let evil =
        B64.encode(br#"{"iss":"secret-custodian","jti":"x","sub":"m","role":"developer","iat":1}"#);
    assert!(s
        .verify(&format!("{}.{}.{}", parts[0], evil, parts[2]))
        .is_err());
}

#[test]
fn alg_none_and_malformed_tokens_are_rejected() {
    let (_d, _v, s) = svc();
    let h = B64.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let p =
        B64.encode(br#"{"iss":"secret-custodian","jti":"x","sub":"m","role":"developer","iat":1}"#);
    assert!(s.verify(&format!("{h}.{p}.")).is_err());
    for bad in ["", "a", "a.b", "a.b.c", "....", "💥.💥.💥"] {
        assert!(s.verify(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn listing_never_exposes_the_token() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", None).unwrap();
    let json = serde_json::to_string(&s.list().unwrap()).unwrap();
    assert!(!json.contains(&t.token));
    assert!(json.contains(&t.jti));
}

// ---- extra tests beyond the plan ----

#[test]
fn forge_helper_control_case_is_accepted() {
    // Guards the negative tests below: a correctly signed, registered token with the exact
    // header is valid, so the rejections below are due to the property under test.
    let (_d, v, s) = svc();
    register(&v, "j1");
    let tok = forge(
        &v,
        GOOD_HEADER,
        r#"{"iss":"secret-custodian","jti":"j1","sub":"m","role":"r","iat":1}"#,
    );
    assert!(s.verify(&tok).is_ok());
}

#[test]
fn token_from_one_vault_does_not_verify_on_another() {
    let (_d, _v, s) = svc();
    let (_d2, _v2, other) = svc();
    let t = s.issue("m", "r", None).unwrap();
    assert!(matches!(other.verify(&t.token), Err(AuthError::Invalid)));
}

#[test]
fn header_variants_with_valid_signature_are_rejected() {
    let (_d, v, s) = svc();
    register(&v, "j1");
    let payload = r#"{"iss":"secret-custodian","jti":"j1","sub":"m","role":"r","iat":1}"#;
    for h in [
        r#"{"alg": "EdDSA","typ":"JWT"}"#,
        r#"{"typ":"JWT","alg":"EdDSA"}"#,
        r#"{"alg":"EdDSA"}"#,
        r#"{"alg":"none","typ":"JWT"}"#,
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"alg":"EdDSA","typ":"JWT"} "#,
        "",
    ] {
        let tok = forge(&v, h, payload);
        assert!(matches!(s.verify(&tok), Err(AuthError::Invalid)), "{h:?}");
    }
}

#[test]
fn issuer_mismatch_is_rejected() {
    let (_d, v, s) = svc();
    register(&v, "j1");
    let tok = forge(
        &v,
        GOOD_HEADER,
        r#"{"iss":"someone-else","jti":"j1","sub":"m","role":"r","iat":1}"#,
    );
    assert!(matches!(s.verify(&tok), Err(AuthError::Invalid)));
}

#[test]
fn unknown_jti_is_invalid_not_revoked() {
    let (_d, v, s) = svc();
    let tok = forge(
        &v,
        GOOD_HEADER,
        r#"{"iss":"secret-custodian","jti":"ghost","sub":"m","role":"r","iat":1}"#,
    );
    assert!(matches!(s.verify(&tok), Err(AuthError::Invalid)));
}

#[test]
fn missing_claims_and_wrong_types_are_rejected() {
    let (_d, v, s) = svc();
    register(&v, "j1");
    for p in [
        r#"{"iss":"secret-custodian","jti":"j1","sub":"m","iat":1}"#,
        r#"{"iss":"secret-custodian","jti":"j1","sub":"m","role":"r"}"#,
        r#"{"iss":"secret-custodian","jti":"j1","sub":"m","role":"r","iat":"1"}"#,
        r#"{"iss":"secret-custodian","jti":"j1","sub":"m","role":"r","iat":1,"exp":"never"}"#,
        r#"[]"#,
        "not json",
        "",
    ] {
        let tok = forge(&v, GOOD_HEADER, p);
        assert!(matches!(s.verify(&tok), Err(AuthError::Invalid)), "{p:?}");
    }
}

#[test]
fn exp_in_the_past_present_and_future() {
    let (_d, v, s) = svc();
    register(&v, "j1");
    let now = sg_core::now();
    let mk = |exp: i64| {
        forge(
            &v,
            GOOD_HEADER,
            &format!(
                r#"{{"iss":"secret-custodian","jti":"j1","sub":"m","role":"r","iat":1,"exp":{exp}}}"#
            ),
        )
    };
    assert!(matches!(
        s.verify(&mk(now - 10)),
        Err(AuthError::Expired(_))
    ));
    assert!(
        matches!(s.verify(&mk(now)), Err(AuthError::Expired(_))),
        "exp == now is expired"
    );
    assert!(s.verify(&mk(now + 3600)).is_ok());
}

#[test]
fn zero_ttl_token_is_immediately_expired() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", Some(Duration::from_secs(0))).unwrap();
    assert!(matches!(s.verify(&t.token), Err(AuthError::Expired(_))));
}

#[test]
fn revoked_unexpired_token_reports_revoked() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", Some(Duration::from_secs(3600))).unwrap();
    s.revoke(&t.jti).unwrap();
    assert!(matches!(s.verify(&t.token), Err(AuthError::Revoked(_))));
}

#[test]
fn expiry_is_evaluated_before_the_revocation_lookup() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", Some(Duration::ZERO)).unwrap();
    s.revoke(&t.jti).unwrap();
    assert!(matches!(s.verify(&t.token), Err(AuthError::Expired(_))));
}

fn token_count(v: &Vault) -> i64 {
    v.conn()
        .query_row("SELECT COUNT(*) FROM tokens", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn out_of_range_ttl_is_rejected_without_inserting_a_row() {
    let (_d, v, s) = svc();
    let huge = [
        Duration::from_secs(u64::MAX),
        Duration::from_secs(i64::MAX as u64),
        // fits in i64 but iat + ttl overflows
        Duration::from_secs(i64::MAX as u64 - 1),
    ];
    for ttl in huge {
        assert!(
            matches!(s.issue("m", "r", Some(ttl)), Err(AuthError::InvalidTtl)),
            "{ttl:?}"
        );
    }
    assert_eq!(token_count(&v), 0);
    assert_eq!(AuthError::InvalidTtl.to_string(), "ttl out of range");
    let ok = s.issue("m", "r", Some(Duration::from_secs(3600))).unwrap();
    assert!(s.verify(&ok.token).is_ok());
    assert!(s.issue("m", "r", Some(Duration::ZERO)).is_ok());
    assert_eq!(token_count(&v), 2);
}

#[test]
fn wrong_length_signing_key_blob_maps_to_crypto_error() {
    let dir = tempdir().unwrap();
    let v = Arc::new(
        Vault::init(
            &dir.path().join("v.db"),
            KeyInput::Raw(crypto::random_key()),
        )
        .unwrap(),
    );
    for len in [0usize, 31, 33, 64] {
        let blob = v.seal_value(b"sg:token-signing-key", &vec![7u8; len]);
        v.conn()
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('token_signing_key', ?1)",
                [blob],
            )
            .unwrap();
        assert!(
            matches!(
                TokenService::new(v.clone()),
                Err(AuthError::Core(sg_core::CoreError::Crypto))
            ),
            "len {len}"
        );
    }
}

#[test]
fn concurrent_service_creation_converges_on_one_key() {
    let (_d, v, _s) = svc();
    // sequential: a second service on the same vault verifies the first's tokens and vice versa
    let a = TokenService::new(v.clone()).unwrap();
    let b = TokenService::new(v.clone()).unwrap();
    let ta = a.issue("m", "r", None).unwrap();
    let tb = b.issue("m", "r", None).unwrap();
    assert!(b.verify(&ta.token).is_ok());
    assert!(a.verify(&tb.token).is_ok());
}

#[test]
fn racing_first_creators_converge_on_one_key() {
    for _ in 0..20 {
        let dir = tempdir().unwrap();
        let v = Arc::new(
            Vault::init(
                &dir.path().join("v.db"),
                KeyInput::Raw(crypto::random_key()),
            )
            .unwrap(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let spawn = |v: Arc<Vault>, bar: Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                bar.wait();
                TokenService::new(v).unwrap()
            })
        };
        let h1 = spawn(v.clone(), barrier.clone());
        let h2 = spawn(v.clone(), barrier.clone());
        let (a, b) = (h1.join().unwrap(), h2.join().unwrap());
        let ta = a.issue("m", "r", None).unwrap();
        let tb = b.issue("m", "r", None).unwrap();
        assert!(b.verify(&ta.token).is_ok());
        assert!(a.verify(&tb.token).is_ok());
        let n: i64 = v
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE key = 'token_signing_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }
}

#[test]
fn non_canonical_or_padded_signature_is_rejected() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", None).unwrap();
    let parts: Vec<&str> = t.token.split('.').collect();
    let sig = parts[2];
    assert_eq!(sig.len(), 86); // 64 bytes -> 86 chars, last char carries 4 unused bits
    let last = sig.chars().last().unwrap();
    let idx = |c: char| {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .find(c)
            .unwrap()
    };
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .chars()
        .collect();
    // flip a trailing (non-canonical) bit in the last character
    let noncanon = alphabet[idx(last) ^ 1];
    let bad = format!("{}.{}.{}{}", parts[0], parts[1], &sig[..85], noncanon);
    assert!(s.verify(&bad).is_err());
    // '=' padding
    let padded = format!("{}.{}.{}==", parts[0], parts[1], sig);
    assert!(s.verify(&padded).is_err());
    // control: the untouched token is fine
    assert!(s.verify(&t.token).is_ok());
}

#[test]
fn single_flipped_signature_byte_is_rejected() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", None).unwrap();
    let parts: Vec<&str> = t.token.split('.').collect();
    let mut sig = B64.decode(parts[2]).unwrap();
    for i in [0usize, 31, 32, 63] {
        sig[i] ^= 0x01;
        let bad = format!("{}.{}.{}", parts[0], parts[1], B64.encode(&sig));
        assert!(
            matches!(s.verify(&bad), Err(AuthError::Invalid)),
            "byte {i}"
        );
        sig[i] ^= 0x01;
    }
}

#[test]
fn odd_machine_and_role_strings_roundtrip_exactly() {
    let (_d, _v, s) = svc();
    for (m, r) in [
        ("lap\"top\\", "dev\nrole"),
        ("héllo 💥", "ロール"),
        ("a.b.c", "x.y.z"),
        ("", ""),
        ("</script>'; DROP TABLE tokens;--", "r\u{0}x"),
    ] {
        let t = s.issue(m, r, None).unwrap();
        let id = s.verify(&t.token).unwrap();
        assert_eq!((id.machine.as_str(), id.role.as_str()), (m, r));
    }
    assert_eq!(s.list().unwrap().len(), 5);
}

#[test]
fn revoke_unknown_or_already_revoked_is_not_found() {
    let (_d, _v, s) = svc();
    assert!(matches!(
        s.revoke("nope"),
        Err(AuthError::Core(sg_core::CoreError::NotFound))
    ));
    let t = s.issue("m", "r", None).unwrap();
    s.revoke(&t.jti).unwrap();
    assert!(matches!(
        s.revoke(&t.jti),
        Err(AuthError::Core(sg_core::CoreError::NotFound))
    ));
    assert_eq!(s.revoke_machine("m").unwrap(), 0);
}

#[test]
fn stored_hash_is_sha256_hex_and_never_the_token() {
    let (_d, v, s) = svc();
    let t = s.issue("m", "r", None).unwrap();
    let h: String = v
        .conn()
        .query_row(
            "SELECT token_hash FROM tokens WHERE jti = ?1",
            [&t.jti],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(h.len(), 64);
    assert!(h
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_ne!(h, t.token);
    assert!(!h.contains(&t.token));
    // the raw signing key / token never sit in plaintext in the meta table either
    let blob: Vec<u8> = v
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'token_signing_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(blob.as_slice(), signing_key(&v).to_bytes().as_slice());
    assert!(
        blob.len() > 32,
        "stored blob must be an AEAD ciphertext (nonce+tag)"
    );
}

#[test]
fn signing_key_is_bound_to_its_aad() {
    let (_d, v, _s) = svc();
    let blob: Vec<u8> = v
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'token_signing_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(v.open_value(b"sg:token-signing-key", &blob).is_ok());
    assert!(v.open_value(b"sg:other", &blob).is_err());
}

#[test]
fn very_long_and_hostile_inputs_do_not_panic() {
    let (_d, _v, s) = svc();
    let long = "a".repeat(2_000_000);
    assert!(s.verify(&long).is_err());
    assert!(s.verify(&format!("{long}.{long}.{long}")).is_err());
    let inputs = [
        "\u{0}.\u{0}.\u{0}",
        "é.é.é",
        "a.b.c.d",
        ".. .",
        " . . ",
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..",
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.e30.AAAA",
        "\r\n.\r\n.\r\n",
    ];
    for i in inputs {
        assert!(s.verify(i).is_err(), "{i:?}");
    }
}

#[test]
fn wrong_signature_length_is_rejected() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", None).unwrap();
    let mut parts: Vec<String> = t.token.split('.').map(String::from).collect();
    parts[2] = B64.encode([0u8; 63]);
    assert!(s.verify(&parts.join(".")).is_err());
    parts[2] = B64.encode([0u8; 65]);
    assert!(s.verify(&parts.join(".")).is_err());
    parts[2] = String::new();
    assert!(s.verify(&parts.join(".")).is_err());
}

#[test]
fn listing_reports_metadata_and_revocation() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", Some(Duration::from_secs(60))).unwrap();
    s.revoke(&t.jti).unwrap();
    let l = s.list().unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(
        (l[0].jti.as_str(), l[0].machine.as_str(), l[0].role.as_str()),
        (t.jti.as_str(), "m", "r")
    );
    assert!(l[0].expires_at.is_some() && l[0].revoked_at.is_some());
}

#[test]
fn expired_and_revoked_errors_carry_the_verified_identity() {
    let (_d, _v, s) = svc();
    let e = s.issue("laptop", "dev", Some(Duration::ZERO)).unwrap();
    match s.verify(&e.token) {
        Err(AuthError::Expired(id)) => {
            assert_eq!(
                (id.jti.as_str(), id.machine.as_str(), id.role.as_str()),
                (e.jti.as_str(), "laptop", "dev")
            );
        }
        other => panic!("expected Expired, got {other:?}"),
    }
    let r = s.issue("ci", "reviewer", None).unwrap();
    s.revoke(&r.jti).unwrap();
    match s.verify(&r.token) {
        Err(AuthError::Revoked(id)) => {
            assert_eq!(
                (id.jti.as_str(), id.machine.as_str(), id.role.as_str()),
                (r.jti.as_str(), "ci", "reviewer")
            );
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn error_display_text_is_unchanged() {
    let id = sg_auth::Identity {
        jti: "j".into(),
        machine: "m".into(),
        role: "r".into(),
    };
    assert_eq!(AuthError::Expired(id.clone()).to_string(), "token expired");
    assert_eq!(AuthError::Revoked(id).to_string(), "token revoked");
}
