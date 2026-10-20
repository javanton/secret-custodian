#![no_main]
use libfuzzer_sys::fuzz_target;
use sg_auth::{TokenService, TokenVerifier};
use std::sync::{Arc, OnceLock};

struct Fixture {
    svc: TokenService,
    good: String,
    jti: String,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let svc = TokenService::new(Arc::clone(&sg_fuzz::temp_vault())).expect("token service");
        let t = svc.issue("machine", "role", None).expect("issue");
        Fixture { svc, good: t.token, jti: t.jti }
    })
}

// Mode 0: the input is the token string. Mode 1: start from a genuine token and apply byte edits
// (overwrite / insert / delete) driven by the input. Anything that is not byte-identical to the
// genuine token must be refused; the genuine token must verify.
fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else { return };
    let candidate: Vec<u8> = if mode & 1 == 0 {
        rest[..rest.len().min(4096)].to_vec()
    } else {
        let mut t = f.good.clone().into_bytes();
        for op in rest.chunks(3).take(8) {
            if t.is_empty() {
                break;
            }
            let pos = op.get(1).copied().unwrap_or(0) as usize % t.len();
            let val = op.get(2).copied().unwrap_or(0);
            match op[0] % 3 {
                0 => t[pos] = val,
                1 => t.insert(pos, val),
                _ => {
                    t.remove(pos);
                }
            }
        }
        t
    };
    let candidate = String::from_utf8_lossy(&candidate).into_owned();
    let res = f.svc.verify(&candidate);
    if candidate == f.good {
        assert_eq!(res.expect("genuine token must verify").jti, f.jti);
    } else {
        assert!(res.is_err(), "non-minted token accepted: {candidate:?}");
    }
});
