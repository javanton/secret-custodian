//! Own test binary: `tracing` caches callsite interest process-wide, so capturing events is only
//! reliable when no other test runs in the same process.
mod common;
use common::*;
use sg_policy::*;

const HOST: &str = "api.example.test";

fn add_header_rule(env: &Env, methods: &[&str]) -> String {
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "developer".into(),
            host_pattern: HOST.into(),
            path_pattern: "*".into(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            kind: InjectionKind::Header,
            target_name: "Authorization".into(),
            template: "Bearer {secret}".into(),
            secret_id: s.id,
        },
    )
    .unwrap();
    env.token("laptop", "developer")
}

/// Captures every tracing event of the test (current-thread runtime, so spawned proxy tasks log
/// into the same thread-local subscriber).
#[derive(Clone, Default)]
struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn logs_never_contain_the_secret_or_the_token() {
    let buf = Buf::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );
    // Untrusted upstream CA: the upstream failure path logs.
    let up = spawn_tls_upstream(HOST).await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert(HOST.into(), up.addr);
    let env = Env::new(cfg).await;
    env.ca.allow_domain(HOST).unwrap();
    let t = add_header_rule(&env, &["GET"]);
    let failed = proxy_request(&env, &t, HOST, "GET", "/", &[], vec![], false).await;
    let forbidden = proxy_request(&env, &t, HOST, "POST", "/", &[], vec![], false).await;
    assert_eq!((failed.status, forbidden.status), (502, 403));

    // A trusted upstream for the successful injection.
    let (env2, _up2) = env_with_upstream(HOST).await;
    let t2 = add_header_rule(&env2, &[]);
    assert_eq!(
        proxy_request(&env2, &t2, HOST, "GET", "/", &[], vec![], false)
            .await
            .status,
        200
    );

    let logs = String::from_utf8_lossy(&buf.0.lock().unwrap()).to_string();
    assert!(
        logs.contains("upstream failure"),
        "capture must work: {logs}"
    );
    for needle in ["REAL-SECRET", t.as_str(), t2.as_str()] {
        assert!(!logs.contains(needle), "log leaked {needle}");
    }
}
